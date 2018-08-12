all:arp_spoof

arp_spoof: arp_spoof.o
	gcc -o arp_spoof arp_spoof.o -lpcap -lpthread

arp_spoof.o:
	gcc -c -o arp_spoof.o arp_spoof.c

clean:
	rm -f *.o
	rm -f arp_spoof

