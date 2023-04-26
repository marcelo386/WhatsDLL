#define _CRT_SECURE_NO_WARNINGS
#include "crypto-aes256.h"
#include "crypto-base64.h"
#include "crypto-hex.h"
#include "crypto-sha256-hkdf.h"
#include "crypto-sha256-hmac.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dec.h"

#if defined(WIN32) || defined(_WIN32)
#define snprintf _snprintf
#endif

enum MediaType {
	MediaType_Unknown,
	MediaType_Image,
	MediaType_Video,
	MediaType_Audio,
	MediaType_Text,
};

int Inited = 0;
char TextMessage[256];
void (*MainCallback)(int) = NULL;  

struct configuration {
	size_t mediakey_length;
	unsigned char mediakey[32];
	char infilename[512];
	char outfilename[512];
	size_t mediatype;
};

static enum MediaType get_media_type(const char *filename) {
	static const char *types[6][32] = {
		{0},
		{"image", ".gif", ".jpg", ".jpeg", ".png", ".tiff", ".raw", ".svg", 0},
		{"video",      ".mp4", ".mpeg", ".mpg", ".mpeg4", ".mpv", ".qt",
		 ".quicktime", ".vc1", ".flv",  ".vob", ".ogg",   ".ogv", ".avi",
		 ".mov",       ".wmv", ".m4p",  ".m4v", ".3gp",   ".3g2", 0},
		{"audio", ".mp3", ".aiff", ".aac", ".flac", ".wav", ".webm", 0},
		{"text", ".doc", ".pdf", ".txt", ".zip", ".rar", 0},
		{0} };
	size_t i;

	for (i = 0; i < 5; i++) {
		size_t j;
		for (j = 0; types[i][j]; j++) {
			const char *ext = types[i][j];
			if (strcmp(ext, filename + strlen(filename) - strlen(ext)) == 0)
				return i;
		}
	}
	return 0;
}

static void parse_param(struct configuration *cfg, const char *name,
	const char *value) {
	if (strcmp(name, "key") == 0 || strcmp(name, "mediakey") == 0) {
		cfg->mediakey_length =
			hex_decode(value, cfg->mediakey, sizeof(cfg->mediakey));
		if (cfg->mediakey_length == sizeof(cfg->mediakey))
			return;

		cfg->mediakey_length = base64_decode(
			cfg->mediakey, sizeof(cfg->mediakey), value, strlen(value));
		if (cfg->mediakey_length == sizeof(cfg->mediakey))
			return;

		sprintf(TextMessage,
			"[-] invalid key, need %u-bytes encoded as hex or base64\n",
			(unsigned)sizeof(cfg->mediakey));
		return;
	}
	else if (strcmp(name, "in") == 0 || strcmp(name, "filename") == 0 ||
		strcmp(name, "infilename") == 0) {
		if (strlen(value) + 1 >= sizeof(cfg->infilename)) {
			sprintf(TextMessage, "[-] infilename too long\n");
			return;
		}
		snprintf(cfg->infilename, sizeof(cfg->infilename), "%s", value);
	}
	else if (strcmp(name, "out") == 0 || strcmp(name, "outfilename") == 0) {
		if (strlen(value) + 1 >= sizeof(cfg->outfilename)) {
			sprintf(TextMessage, "[-] outfilename too long\n");
			return;
		}
		snprintf(cfg->outfilename, sizeof(cfg->outfilename), "%s", value);
		if (cfg->mediatype == 0)
			cfg->mediatype = get_media_type(cfg->outfilename);
	}
	else if (strcmp(name, "type") == 0 || strcmp(name, "mediatype") == 0) {
		size_t t = get_media_type(value);
		if (t == 0) {
			sprintf(TextMessage,
				"[-] unknown media type=%s. Valid parms: video, audio, "
				"image, doc\n",
				value);
			return;
		}
		cfg->mediatype = t;
	}
	else {
		sprintf(TextMessage, "[-] unknown parameter: --%s (try --help)\n", name);
		return;
	}
	return;
}

struct configuration parse_command_line(int argc, char *argv[]) {
	int i;
	struct configuration cfg = { 0, {0}, {0}, {0}, 0 };

	for (i = 1; i < argc; i++) {
		
		if (argv[i][0] != '-') {
			sprintf(TextMessage, "[-] unexpected param: %s\n", argv[i]);
			break;
		}
		switch (argv[i][1]) {
		case '-':
			if (i + 1 < argc) {
				parse_param(&cfg, argv[i] + 2, argv[i + 1]);
				i++;
			}
			else {
				sprintf(TextMessage, "[-] missing expected parameter after '%s'\n",
					argv[i]);
			}
			break;
		default:
			sprintf(TextMessage, "[-] invalid parameter: -%c (try -h for help)\n",
				argv[i][1]);
			break;
		}
	}
	return cfg;
}

void decrypt_stream(FILE *fp_in, FILE *fp_out, const unsigned char *mediakey,
	size_t mediakey_length, enum MediaType mediatype) {
	unsigned char prevblock[16];
	size_t bytes_read;
	size_t bytes_written;
	struct AES_ctx ctx;
	HMAC_CTX hmac;
	SHA256_CTX filesha_ctx, encsha_ctx;
	unsigned char okm[112] = { 0 };
	unsigned char iv[16] = { 0 };
	unsigned char aeskey[32] = { 0 };
	unsigned char mackey[32] = { 0 };
	unsigned padding_length;
	unsigned last_length;
	unsigned char tmp[32];
	unsigned char block[16];
	int fsz = 0;
	int percent = 0;
	int oldpercent = 0;

	static const char *infostrings[6] = {
		"WhatsApp Video Keys", "WhatsApp Image Keys",    "WhatsApp Video Keys",
		"WhatsApp Audio Keys", "WhatsApp Document Keys", 0 };
	const char *info = infostrings[mediatype];

	crypto_hkdf(0, 0, mediakey, mediakey_length, info, strlen(info), okm,
		sizeof(okm));
	memcpy(iv, okm + 0, sizeof(iv));
	memcpy(aeskey, okm + 16, sizeof(aeskey));
	memcpy(mackey, okm + 48, sizeof(mackey));

	AES_init_ctx_iv(&ctx, aeskey, iv);
	hmac_sha256_init(&hmac, mackey, 32);
	hmac_sha256_update(&hmac, iv, 16);
	SHA256_Init(&filesha_ctx);
	SHA256_Init(&encsha_ctx);
	
	if (MainCallback != NULL) {	
		fseek(fp_in, 0, SEEK_END);
		fsz = ftell(fp_in);
		fseek(fp_in, 0, SEEK_SET);
	}
	
	bytes_read = fread(prevblock, 1, sizeof(prevblock), fp_in);
	SHA256_Update(&encsha_ctx, prevblock, bytes_read);
	if (bytes_read != sizeof(prevblock)) {
		sprintf(TextMessage,"[-] file too short (%u bytes read, expected at least 16)\n",
			(unsigned)bytes_read);
		return;
	}

	hmac_sha256_update(&hmac, prevblock, bytes_read);
	AES_CBC_decrypt_buffer(&ctx, prevblock, bytes_read);

	for (;;) {

		bytes_read = fread(block, 1, sizeof(block), fp_in);
		SHA256_Update(&encsha_ctx, block, bytes_read);

		if (bytes_read != sizeof(block))
			break;

		SHA256_Update(&filesha_ctx, prevblock, bytes_read);
		bytes_written = fwrite(prevblock, 1, bytes_read, fp_out);
		if (bytes_written != bytes_read) {
			sprintf(TextMessage,"[-] error writing decrypted output\n");
			return;
		}

		if (MainCallback != NULL) {
			percent = (int)((ftell(fp_in) * 100) / fsz);
			if (oldpercent != percent) MainCallback(percent);
			oldpercent = percent;
		}

		memcpy(prevblock, block, bytes_read);
		hmac_sha256_update(&hmac, prevblock, bytes_read);
		AES_CBC_decrypt_buffer(&ctx, prevblock, bytes_read);
	}

	if (MainCallback != NULL) MainCallback(100);

	if (bytes_read != 10) {
		sprintf(TextMessage,"[-] expected 10 remaining bytes at end of file, found %u\n",
			(unsigned)bytes_read);
		return;
	}

	padding_length = prevblock[15];
	if (padding_length > 16) {
		sprintf(TextMessage,"[-] invalid padding length: %u (must be 16 or less)\n",
			padding_length);
		padding_length = 16;
	}

	last_length = sizeof(prevblock) - padding_length;

	SHA256_Update(&filesha_ctx, prevblock, last_length);
	bytes_written = fwrite(prevblock, 1, last_length, fp_out);
	if (bytes_written != last_length) {
		sprintf(TextMessage,"[-] error writing decrypted output\n");
		return;
	}

	hmac_sha256_final(&hmac, tmp, sizeof(tmp));
	if (memcmp(block, tmp, 10) == 0) {
	}
	else {
		sprintf(TextMessage,"[-] match failed (file corrupted)\n");
	}

	SHA256_Final(tmp, &filesha_ctx);
	SHA256_Final(tmp, &encsha_ctx);
}

extern int __cdecl InitModule(int SecurityCode)
{
	if (SecurityCode == 18352456) Inited = SecurityCode; 
	return SecurityCode;
}

extern int __cdecl Decrypt(int argc, char *argv[], void (Callback)(int), char **ErrorText)
{
	struct configuration cfg;
	FILE *fp_in;
	FILE *fp_out;
	static const char *medianames[6] = { "video", "image", "video", "audio", "text",  "unknown" };
	
	memset(TextMessage, 0, sizeof(TextMessage));
	*ErrorText = TextMessage;
	MainCallback = Callback;
	
	if (Inited != 18352456) return 1;
	
	cfg = parse_command_line(argc, argv);
	if (TextMessage[0] != 0) return 1;

	if (cfg.mediakey_length == 0) {
		sprintf(TextMessage, "[-] missing key, use '--key' parameter\n");
		return 1;
	}
	if (cfg.infilename[0] == '\0') {
		sprintf(TextMessage,
			"[-] missing input file, use '--in' parameter\n");
		return 1;
	}
	if (cfg.outfilename[0] == '\0') {
		sprintf(TextMessage,
			"[-] missing output file, use '--out' parameter\n");
		return 1;
	}
	if (cfg.mediatype == 0) {
		sprintf(TextMessage,
			"[-] unknown media type, use '--type' parameter"
			" with 'video', 'image', 'audio', or 'text'\n");
		return 1;
	}

	fp_in = fopen(cfg.infilename, "rb");
	if (fp_in == NULL) {
		sprintf(TextMessage,"[-] %s: %s\n", cfg.infilename, strerror(errno));
		return 1;
	}
	fp_out = fopen(cfg.outfilename, "wb");
	if (fp_out == NULL) {
		fclose(fp_in);
		sprintf(TextMessage,"[-] %s: %s\n", cfg.outfilename, strerror(errno));
		return 1;
	}

	long tamanho;
	if (fp_in != NULL) {
		fseek(fp_in, 0, SEEK_END);
		tamanho = ftell(fp_in);
	}

	//if (tamanho < 800000) {
	//	decrypt_stream(fp_in, fp_out, cfg.mediakey, cfg.mediakey_length, cfg.mediatype);
	//}


	decrypt_stream(fp_in, fp_out, cfg.mediakey, cfg.mediakey_length, cfg.mediatype);

	fclose(fp_in);
	fclose(fp_out);
	if (TextMessage[0] != 0) return 1; else return 0;
}
