#!/bin/bash
# Build with i686-w64-mingw32-gcc-win32 in debian for example
rm *.o
rm ../invictus.exe
i686-w64-mingw32-gcc-win32 -O0 -o main.o -c main.c
i686-w64-mingw32-gcc-win32 -O0 -o invictus.exe main.o "-Wl,--nxcompat,--dynamicbase" -lws2_32
strip -s invictus.exe
mv invictus.exe ../
