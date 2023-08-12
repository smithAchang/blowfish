.PHONY: test


vpath %.h .:..
vpath %.c .:..

test: test.c blowfish.c
	@echo "build blowfish api testing program ..."
	gcc -g3 -O0 -D__LINUX -W -Wall -Wno-pointer-sign -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast -Wno-unused-variable -Wno-unused-parameter -I.. $^ -o $@ 
