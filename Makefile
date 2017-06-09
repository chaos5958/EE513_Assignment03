all: nids snort http
	g++ -o ../bin/my_nids ../bin/nids_hhyeo.o ../bin/snort_parser.o ../bin/http_parser.o -lpcap -I/usr/include/pcap -pthread

nids: 
	g++ -c -o ../bin/nids_hhyeo.o nids_hhyeo.cpp -I/home/ubuntu/homework -std=c++11
snort:
	g++ -c -o ../bin/snort_parser.o snort_parser.cpp -std=c++11 
http:
	g++ -c -o ../bin/http_parser.o ../lib/http-parser/http_parser.c -std=c++11


clean:
	rm ../bin/my_nids ../bin/nids_hhyeo.o ../bin/snort_parser.o

