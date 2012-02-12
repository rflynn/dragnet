
all: dragnet.so client

dragnet.so: dragnet.c
	$(CC) -Wall -O2 -fpic -shared -ldl -o dragnet.so dragnet.c

client: client.o

clean:
	$(RM) dragnet.so *.o client
