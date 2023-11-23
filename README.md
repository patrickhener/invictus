# invictus

I coded this little vulnerable app as a practice app for OSED. This app is compiled with `-Wl,--nxcompat,--dynamicbase` (ASLR, DEP) and stripped so you can throw it into IDA and practice Reverse Engineering. You can identify one possibility to leak addresses. Also it has one stack overflow vulnerability in it.

For better experience it is recommended to neither look at the source nor the solution until you solved it yourself.

If you want to compile it yourself there is a build.sh in the sources. I used `i686-w64-mingw32-gcc-win32` on debian to compile and Visual Studio Code to create the app.

For the best experience run it on Windows 10 32-bit.