all:
	gcc -fno-stack-protector survey.c -o survey
	cp survey ../docker/share
	patchelf --replace-needed libc.so.6 ./libc-2.31.so survey
	patchelf --set-interpreter ./ld-2.31.so survey
	cp libc-2.31.so ld-2.31.so survey ../player