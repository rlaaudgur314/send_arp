all : send_arp

send_arp: arp.o main.o
	g++ -o send_arp main.o arp.o -lpcap

main.o: kmh_header.h main.c
	g++ -c -o main.o main.c

arp.o: kmh_header.h kmh_header.c
	g++ -c -o arp.o kmh_header.c

clean:
	rm *.o send_arp
