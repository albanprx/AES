CFLAGS = -Wall -Wextra
CPPFLAGS = -I ../include/
LDFLAGS =#-lm bibli math 

all: AES

AES: AES.o ECB.o CBC.o CFB.o more.o
	gcc $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o AES AES.o ECB.o CBC.o CFB.o more.o

AES.o: AES.c ../include/AES.h
	gcc $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -c AES.c

ECB.o: ECB.c ../include/ECB.h
	gcc $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -c ECB.c

CBC.o: CBC.c ../include/CBC.h
	gcc $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -c CBC.c

CFB.o: CFB.c ../include/CFB.h
	gcc $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -c CFB.c

more.o: more.c ../include/more.h
	gcc $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -c more.c

clean:
	rm -f *.o AES

help:
	@echo "Targets available:"	
	@echo "	all: generate the AES binary file from the source files"
	@echo "	clean: remove all temporary files + binary file generated by the compilation"
	@echo "	help: display the targets of the Makefile with a short description"

.PHONY: all clean help

