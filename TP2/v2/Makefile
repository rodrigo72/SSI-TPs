CC = gcc
CFLAGS = -Wall -Wextra

all: server client set_permissions

server: server.c
	$(CC) $(CFLAGS) server.c -o s

client: client.c
	$(CC) $(CFLAGS) client.c -o c

set_permissions: server
	sudo rm -rf /tmp/mail_box
	sudo mkdir /tmp/mail_box
	sudo chown root:app /tmp/mail_box
	sudo chmod 770 /tmp/mail_box
	sudo chown root:root s
	sudo chmod u+s s
	sudo setcap cap_chown,cap_setuid,cap_setgid+ep s

clean:
	rm -f s c