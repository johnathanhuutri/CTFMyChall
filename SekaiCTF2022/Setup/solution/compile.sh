#!/bin/sh

gcc -o setup -fstack-protector-all -z relro -z now setup.c -lseccomp
patchelf --set-interpreter ./ld-2.34.so setup
patchelf --replace-needed libc.so.6 ./libc-2.34.so setup
patchelf --replace-needed libseccomp.so.2 ./libseccomp.so.2 setup

# patchelf --set-interpreter /usr/lib/x86_64-linux-gnu/ld-2.34.so setup
# patchelf --replace-needed libc.so.6 /usr/lib/x86_64-linux-gnu/libc-2.34.so setup
# patchelf --replace-needed libseccomp.so.2 /usr/lib/x86_64-linux-gnu/libseccomp.so.2 setup
# cp setup files/home