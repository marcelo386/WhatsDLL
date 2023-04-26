cd c:\
cd C:\Componente\WhatsDLL\

gcc -c -DBUILD_DLL dec.c -o out.o
gcc -shared -o minha.dll out.o -Wl,--out-implib,minha.a

pause

gcc -Wall -shared *.c -o Whats64DLL.dll

pause