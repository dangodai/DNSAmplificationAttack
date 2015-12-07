all:
	gcc -o dns main.c dns.c
clean:
	rm -f dns
