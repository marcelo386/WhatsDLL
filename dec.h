
	__declspec(dllexport) int InitModule(int SecurityCode);
	__declspec(dllexport) int Decrypt(int argc, char *argv[], void (Callback)(int), char **ErrorText);
