CC = gcc
CFLAGS = -Wall -Werror -std=c99 -I/usr/include/libnl3/
LDFLAGS = -lnl-3 -lnl-genl-3 -lpcap

TARGET = scandump
INSTALL_DIR = /usr/local/bin

SRCS = scandump.c

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	install -m 755 $(TARGET) $(INSTALL_DIR)

clean:
	rm -f $(OBJS) $(TARGET)
