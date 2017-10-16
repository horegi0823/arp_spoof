all:arp_spoof.c
	gcc -o arp_spoof arp_spoof.c -lpcap -lpthread

