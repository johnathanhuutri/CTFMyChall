#!/bin/sh

gcc -no-pie -o textsender textsender.c
patchelf --set-interpreter ./ld-2.32.so textsender
patchelf --replace-needed libc.so.6 ./libc-2.32.so textsender