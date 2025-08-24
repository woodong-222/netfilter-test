CC=gcc
CFLAGS=-Wall -g
LIBS=-lnetfilter_queue -lnfnetlink

TARGET=netfilter-test
SOURCE=netfilter-test.c

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: clean