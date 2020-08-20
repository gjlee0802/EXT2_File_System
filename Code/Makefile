SHELLOBJS	= shell.o ext2.o disksim.o ext2_shell.o entrylist.o

all: $(SHELLOBJS)
	$(CC) -o shell $(SHELLOBJS) -Wall

clean:
	rm *.o
	rm shell
