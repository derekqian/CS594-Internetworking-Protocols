# Copyright © 2012 Bart Massey
# [This program is licensed under the "MIT License"]
# Please see the file COPYING in the source
# distribution of this software for license terms.

# [This program is licensed under the "MIT License"]
# Please see the file COPYING in the source
# distribution of this software for license terms.

CFLAGS = -g -Wall -c

all : ftpread

wireguppy : wireguppy.o
	$(CC) -o wireguppy wireguppy.o

ftpread : ftpread.o expect.o
	$(CC) -o ftpread ftpread.o expect.o

wireguppy.o : wireguppy.c
	$(CC) $(CFLAGS) wireguppy.c

ftpread.o : ftpread.c
	$(CC) $(CFLAGS) ftpread.c

expect.o : expect.c
	$(CC) $(CFLAGS) expect.c

test :
	@echo ==================run in passive mode===============
	@./ftpread -passive svcs.cs.pdx.edu hello.txt
	@echo =================run in active mode===============
	@./ftpread -active svcs.cs.pdx.edu hello.txt

clean:
	-rm -f ftpread *.o
