SHELLOBJS	= shell.o ext2.o disksim.o ext2_shell.o entrylist.o

all: $(SHELLOBJS)
	$(CC) -o shell $(SHELLOBJS)
CFLAGS = -ggdb -Wall
CFLAGS+ = -g
clean:
	rm *.o
	rm shell
