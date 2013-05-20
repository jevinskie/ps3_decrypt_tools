CC=g++
CFLAGS=-Wall
LDFLAGS=
SOURCES=lib/aes.c lib/sha1.c lib/des.c lib/aes_omac.cpp lib/kgen.cpp lib/aes_xts.cpp lib/util.cpp lib/keys.cpp lib/indiv.cpp lib/eid.cpp lib/hdd.cpp lib/main.cpp
EXECUTABLE=decrypt_tools
all:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
clean:
	rm -rf $(EXECUTABLE)
