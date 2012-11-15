# Copyright © 2012 Bart Massey
# [This program is licensed under the "MIT License"]
# Please see the file COPYING in the source
# distribution of this software for license terms.

# [This program is licensed under the "MIT License"]
# Please see the file COPYING in the source
# distribution of this software for license terms.

CFLAGS = -g -Wall -c

all : ftpread.o expect.o
	$(CC) -o ftpread ftpread.o expect.o

ftpread.o : ftpread.c
	$(CC) $(CFLAGS) ftpread.c

expect.o : expect.c
	$(CC) $(CFLAGS) expect.c

clean:
	-rm -f ftpread *.o
