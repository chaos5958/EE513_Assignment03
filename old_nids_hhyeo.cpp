#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <ctype.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);

// IP 헤더 구조체
struct ip *iph;

// TCP 헤더 구조체
struct tcphdr *tcph;

int main(int argc, char **argv)
{
    char *dev;
    char *net;
    char *mask;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const u_char *packet;

    struct bpf_program fp;     

    pcap_t *pcd;  // packet capture descriptor

    //First get the list of available devices
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }
    printf("Done");

    //Print the available devices
    printf("\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }

    // 디바이스 이름에 대한 네트웍/마스크 정보를 얻어온다. 
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if (ret == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    // 네트웍/마스트 정보를 점박이 3형제 스타일로 변경한다. 
    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);
    printf("NET : %s\n", net);

    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);
    printf("MSK : %s\n", mask);
    printf("=======================\n");

    // 디바이스 dev 에 대한 packet capture 
    // descriptor 를얻어온다.   
    pcd = pcap_open_live(dev, BUFSIZ,  1, -1, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }    

    /*
    // 컴파일 옵션을 준다.
    if (pcap_compile(pcd, &fp, argv[2], 0, netp) == -1)
    {
        printf("compile error\n");    
        exit(1);
    }
    // 컴파일 옵션대로 패킷필터 룰을 세팅한다. 
    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);    
    }
    */

    // 지정된 횟수만큼 패킷캡쳐를 한다. 
    // pcap_setfilter 을 통과한 패킷이 들어올경우 
    // callback 함수를 호출하도록 한다. 
    pcap_loop(pcd, 0, callback, NULL);
}

/*
 *  * print packet payload data (avoid printing binary data)
 *   */
void print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;/* number of bytes per line */          
    int line_len;
    int offset = 0;/* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}

// 패킷을 받아들일경우 이 함수를 호출한다.  
// packet 가 받아들인 패킷이다.
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, 
                const u_char *packet)
{
    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;    
    int chcnt =0;
    int length=pkthdr->len;
    const u_char *payload;
    int size_payload;


    // 이더넷 헤더를 가져온다. 
    ep = (struct ether_header *)packet;

    // IP 헤더를 가져오기 위해서 
    // 이더넷 헤더 크기만큼 offset 한다.   
    packet += sizeof(struct ether_header);

    // 프로토콜 타입을 알아낸다. 
    ether_type = ntohs(ep->ether_type);

    printf("===========================\n");

    // 만약 IP 패킷이라면 
    if (ether_type == ETHERTYPE_IP)
    {
        // IP 헤더에서 데이타 정보를 출력한다.  
        iph = (struct ip *)packet;
        printf("[IP header]\n");
        printf("Version: %u\n", iph->ip_v);
        printf("Header Length: %u\n", ntohs(iph->ip_hl));
        printf("ToS: 0x%x\n", iph->ip_tos);
        printf("Fragment Offset: %u\n", ntohs(iph->ip_off));
        printf("Source: %s\n", inet_ntoa(iph->ip_src));
        printf("Destination: %s\n", inet_ntoa(iph->ip_dst));
        printf("\n");

        // 만약 TCP 데이타 라면
        // TCP 정보를 출력한다. 
        if (iph->ip_p == IPPROTO_TCP)
        {
            tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
            printf("[TCP header]\n");
            printf("Source Port : %u\n" , ntohs(tcph->source));
            printf("Destination Port : %u\n" , ntohs(tcph->dest));
            printf("Sequence Number: %u\n", ntohl(tcph->th_seq));
            printf("Acknowledgement Number: %u\n", ntohl(tcph->th_ack)); 

            bool isFirst = true, isLast = false;

            printf("Flags: %s%s%s%s%s%s%s%s\n", 
                    (tcph->urg ? (isFirst ? "FIN" : ", FIN") : ""), 
                    (tcph->urg ? (isFirst ? "SYN" : ", SYN") : ""),
                    (tcph->urg ? (isFirst ? "RST" : ", RST") : ""),
                    (tcph->urg ? (isFirst ? "PUSH" : ", PUSH") : ""),
                    (tcph->urg ? (isFirst ? "ACK" :  ", ACK") : ""),
                    (tcph->urg ? (isFirst ? "URG" : ", URG") : ""),
                    (tcph->urg ? (isFirst ? "ECE" : ", ECE") : ""),
                    (tcph->urg ? (isFirst ? "CWR" : ", CWR") : "")
                    );
            printf("\n");

            //printf TCP payload
            payload = (u_char *)(packet + iph->ip_hl * 4 + tcph->th_off * 4);
            size_payload = ntohs(iph->ip_len) - (iph->ip_hl * 4 + tcph->th_off * 4);

            if(size_payload > 0)
            {
                printf("[TCP payload]\n");
                print_payload(payload, size_payload);
            }
        }
    }
    // IP 패킷이 아니라면 
    else
    {
        printf("NONE IP 패킷\n");
    }
    
    printf("===========================\n");

    printf("\n\n");
}    
/*
 *  * print data in rows of 16 bytes: offset   hex   ascii
 *   *
 *    * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 *     */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}
