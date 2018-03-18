CC      = gcc
CFLAGS  = -O3 $(shell pkg-config --cflags libevdev)
RM      = rm
LIBS	= -lpthread -lm $(shell pkg-config --libs libevdev)

PREFIX ?= /usr/local

default: all

all: usb_mouse_to_serial

usb_mouse_to_serial: usb_mouse_to_serial.c
	$(CC) $(CFLAGS) usb_mouse_to_serial.c -o usb_mouse_to_serial $(LIBS)

install: usb_mouse_to_serial
	install -d $(DESTDIR)$(PREFIX)/sbin/
	install -m 755 usb_mouse_to_serial $(DESTDIR)$(PREFIX)/sbin/

uninstall:
	$(RM) $(PREFIX)/sbin/usb_mouse_to_serial

clean:
	$(RM) usb_mouse_to_serial