/*

    Packet sniffer using libpcap library
*/
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include <unistd.h> //for fork()
#include <signal.h>
#include <sys/wait.h>
 
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header

#include <string>
#include <iostream>
#include <vector>
#include <fstream>

#include "snort_parser.h"

#include "../lib/http-parser/http_parser.h"
#include <assert.h>
#include <stdarg.h>
#include <sys/file.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <fcntl.h>

#define RED  "\x1B[31m"
#define NRM  "\x1B[0m"


void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_ip_packet(const u_char * , int, std::map<std::string, std::string> *);
void print_tcp_packet(const u_char *  , int, std::map<std::string, std::string> *);
void print_udp_packet(const u_char * , int, std::map<std::string, std::string> *);
void PrintData (const u_char * , int, std::map<std::string, std::string> *);
bool filter_packet(const u_char *Buffer, int Size, std::map<std::string, std::string> *option_rule);
void parser_init (enum http_parser_type type);
bool is_http_res(const char *payload);
bool is_http_req(const char *payload);
void parser_free ();
int my_url_callback(http_parser* parser, const char *at, size_t length); 
size_t strlncat(char *dst, size_t len, const char *src, size_t n);
void http_parse(const char *payload);


std::string parsed_url;
static http_parser *parser;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j; 
static http_parser_settings settings_null;
static const char *method_strings[] =
{
#define XX(num, name, string) #string,
    HTTP_METHOD_MAP(XX)
#undef XX
};
bool isHttpRule = false;

sem_t *sem = sem_open("sema_hhyeo", O_CREAT|O_EXCL, 0, 1);
 
void handle_ctrlc(int sig){ // can be called asynchronously
    exit(-1);
}

int main(int argc, char **argv)
{
    settings_null.on_message_begin = 0;
    settings_null.on_header_field = 0;
    settings_null.on_header_value = 0;
    settings_null.on_url = my_url_callback;
    settings_null.on_status = 0;
    settings_null.on_body = 0;
    settings_null.on_headers_complete = 0;
    settings_null.on_message_complete = 0;
    settings_null.on_chunk_header = 0;
    settings_null.on_chunk_complete = 0;


    pcap_if_t *alldevsp , *device;
    pcap_t *handle; //Handle of the device that shall be sniffed
 
    char errbuf[100] , *devname , devs[100][100];
    int count = 1, n;
     
    signal(SIGINT, handle_ctrlc);

    //Read snort rules
    std::vector<std::string> snortrules;
    std::string line;

    std::ifstream rulefile(argv[1]);
    if(rulefile.is_open())
    {
        while(getline(rulefile, line))
        {
            std::cout << line << std::endl;
            snortrules.push_back(line);
        }

        rulefile.close();
    }


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

    int pid;
    struct bpf_program fp;   
    bpf_u_int32 netp; 
    bpf_u_int32 maskp;
    snort_parser parser = snort_parser();
    //Handle all snort rules
    for(std::vector<std::string>::iterator iter = snortrules.begin() ; iter != snortrules.end(); iter++)
    {
        std::cout << "iter :" << *iter << std::endl;
        std::cout << "snort rule size: " << snortrules.size() << std::endl;
        parser.clean();
        parser.Parse(*iter);
        std::string filter_rule = parser.getHeaderRule();
        std::map<std::string, std::string> option_rule = parser.getOptionRule();
        
        std::cout << "filter rule: " << filter_rule << std::endl; 

        //Handle all devices using multi-processes by calling fork()
        for(int j = 1 ; j < count ; j++)
        {
            if(!(strcmp(devs[j], "eth0") == 0 | strcmp(devs[j], "lo") == 0))
                continue;

            //Child - execute sniffer for a specific device
            pid = fork();
            if(pid == 0)
            {
                if(parser.isHttp())
                    isHttpRule = true;

                devname = devs[j];

                //Open the device for sniffing
                //printf("Opening device %s for sniffing ... " , devname);

                if(pcap_lookupnet(devname,&netp,&maskp,errbuf) == -1)
                {
                    fprintf(stderr, "%s\n", errbuf);
                    exit(1);
                }

                if ((handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf)) == NULL) 
                {
                    fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
                    exit(1);
                }
                if (pcap_compile(handle, &fp, filter_rule.c_str(), 0, netp) == -1)
                {
                    printf("compile error\n");    
                    exit(1);
                }
                // 컴파일 옵션대로 패킷필터 룰을 세팅한다. 
                if (pcap_setfilter(handle, &fp) == -1)
                {
                    exit(1);    
                }
                //Put the device in sniff loop
                if(parser.getAction().compare("alert") == 0)
                    pcap_loop(handle , -1 , process_packet , reinterpret_cast<u_char *>(&option_rule));
                else
                    std::cerr << "Invalid snort action rule" << std::endl;

                exit(1);

            }
            //Parent - log pid for killing when a program get Ctrl-C signal
            else if(pid > 0)
            {
                //printf("%d child pid: %d\n", j-1, pid);
            }
            else
            {
                fprintf(stderr, "pcap fork failed for: %s\n", devs[j]);
                perror("fork error");
            }
        }
    }
    int wpid, status = 0;

    while((wpid = wait(&status)) > 0);

    sem_unlink("sema_hhyeo");
    sem_close(sem);

    printf("main end\n");
    return 0;   
}
 
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    sem_wait(sem);
    int size = header->len;
    std::map<std::string, std::string> *option_rule = reinterpret_cast<std::map<std::string, std::string> *>(args);

    
    if(!filter_packet(buffer, size, option_rule))
    {
        return;
    }
     
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 6:  //TCP Protocol
            print_tcp_packet(buffer , size, option_rule);
            break;
         
        case 17: //UDP Protocol
            print_udp_packet(buffer , size, option_rule);
            break;
    }

    //Print msg
    auto msg = option_rule->find("msg");
    if(msg != option_rule->end())
        std::cout << "Message: " << msg->second << std::endl;
    sem_post(sem);
}

bool filter_packet(const u_char *Buffer, int Size, std::map<std::string, std::string> *option_rule)
{
    struct iphdr *iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    int iphdrlen =iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    auto tos = option_rule->find("tos");
    auto len = option_rule->find("len");
    auto offset = option_rule->find("offset");
    auto seq = option_rule->find("seq"); 
    auto ack = option_rule->find("ack");
    auto flags = option_rule->find("flags");
    auto http_request = option_rule->find("http_request");
    auto content = option_rule->find("content"); 


    const char* payload = (const char*)(Buffer + header_size);
    std::string payload_str = std::string(payload);

    std::string log_str;


    //IP related options
    if(len != option_rule->end())
    {
        if((unsigned int)(iph->ihl) != atoi((len->second).c_str()))
            return false;

    }

    if(tos != option_rule->end())
    {
        if(iph->tos != atoi((tos->second).c_str()))
            return false;
    }
 
    if(offset != option_rule->end())
    {
        if(ntohs(iph->frag_off) != atoi((offset->second).c_str()))
            return false;
    }

    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 6:  //TCP Protocol
            //seq
            if(seq != option_rule->end())
            {
                if(ntohs(tcph->seq) != atoi((seq->second).c_str()))
                    return false;
            }       

            //ack
            if(ack != option_rule->end())
            {
                if(ntohs(tcph->ack_seq) != atoi((ack->second).c_str()))
                    return false;
            }      

            //flags
            if(flags != option_rule->end())
            {
                std::string flags_str = flags->second;

                if((flags_str.find('F') != std::string::npos) && (tcph->fin == 0))
                    return false;
                
                if((flags_str.find('S') != std::string::npos) && (tcph->syn == 0))
                    return false;

                if((flags_str.find('R') != std::string::npos) && (tcph->rst == 0))
                    return false;

                if((flags_str.find('P') != std::string::npos) && (tcph->psh == 0))
                    return false;

                if((flags_str.find('A') != std::string::npos) && (tcph->ack == 0))
                    return false;
            }

            //payload 
            if(isHttpRule)
            {
                if(!is_http_req(payload) && !is_http_res(payload))
                    return false;
                

                http_parse(payload);

                if(http_request != option_rule->end())
                {
                    std::string request_str = http_request->second;
                    std::string target_str = std::string(method_strings[parser->method]);
                    if(request_str.compare(target_str) != 0) 
                    {
                        printf(RED "request type mismatch\n" NRM); 
                        parser_free();
                        return false;
                    }
                }

                if(content != option_rule->end())
                {
                    std::string payload_str = std::string(payload);
                    std::string target_str = content->second;

                    if(payload_str.find(target_str) == std::string::npos)
                    {
                        printf(RED "content mismatch\n" NRM);
                        parser_free();
                        return false;
                    }
                }
                parser_free();
            }
            break;
         
        case 17:   //UDP Protocol
            break;
    }

    return true;
}
 
void print_ip_header(const u_char * Buffer, int Size, std::map<std::string, std::string> *option_rule)
{
    unsigned short iphdrlen;
    auto tos = option_rule->find("tos");
    auto len = option_rule->find("len");
    auto offset = option_rule->find("offset");
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("[IP header]\n");
    printf("Version: %u\n", (unsigned int)iph->version);

    if(len != option_rule->end())
    {
        if((unsigned int)(iph->ihl) == atoi((len->second).c_str()))
            printf(RED "Header Length: %u (%u bytes)\n" NRM, (unsigned int)(iph->ihl), (unsigned int)(iph->ihl)*4); //Bytes length
    }
    else
        printf("Header Length: %u (%u bytes)\n", (unsigned int)(iph->ihl), (unsigned int)(iph->ihl)*4); //Bytes length

    if(tos != option_rule->end())
    {
        if(iph->tos == atoi((tos->second).c_str()))
            printf(RED "ToS: 0x%x\n" NRM, iph->tos);
    }
    else
        printf("ToS: 0x%x\n", iph->tos);

      //IP related options
    if(offset != option_rule->end())
    {
        if(ntohs(iph->frag_off) == atoi((offset->second).c_str()))
            printf(RED "Fragment Offset: %u\n" NRM, ntohs(iph->frag_off));
    }
    else     
        printf("Fragment Offset: %u\n", ntohs(iph->frag_off));

    printf("Source: %s\n", inet_ntoa(source.sin_addr));
    printf("Destination: %s\n", inet_ntoa(dest.sin_addr));
    printf("\n");
}
 
void print_tcp_packet(const u_char * Buffer, int Size, std::map<std::string, std::string> *option_rule) 
{
    auto seq = option_rule->find("seq"); 
    auto ack = option_rule->find("ack");
    auto flags = option_rule->find("flags");

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    printf("===========================\n");
    print_ip_header(Buffer,Size, option_rule);

    printf("[TCP header]\n");
    printf("Source Port : %u\n" , ntohs(tcph->source));
    printf("Destination Port : %u\n" , ntohs(tcph->dest));
    //seq
    if(seq != option_rule->end())
    {
        if(ntohs(tcph->seq) == atoi((seq->second).c_str()))
            printf(RED "Sequence Number: %u\n" NRM, ntohl(tcph->seq));

    }       
    else
        printf("Sequence Number: %u\n", ntohl(tcph->seq));

    //ack
    if(ack != option_rule->end())
    {
        if(ntohs(tcph->ack_seq) == atoi((ack->second).c_str()))
            printf(RED "Acknowledgement Number: %u\n" NRM, ntohl(tcph->ack_seq)); 
    }      
    else
        printf("Acknowledgement Number: %u\n", ntohl(tcph->ack_seq)); 


    /*
    bool isFirst = true, isLast = false;
    printf("Flags: %s%s%s%s%s%s%s%s\n", 
            (tcph->urg) ? (isFirst ? "FIN" : ", FIN") : ""), 
            (tcph->syn? (isFirst ? "SYN" : ", SYN") : ""),
            (tcph->rst? (isFirst ? "RST" : ", RST") : ""),
            (tcph->psh? (isFirst ? "PUSH" : ", PUSH") : ""),
            (tcph->ack? (isFirst ? "ACK" :  ", ACK") : ""),
            (tcph->urg? (isFirst ? "URG" : ", URG") : ""),
            (tcph->ece? (isFirst ? "ECE" : ", ECE") : ""),
            (tcph->cwr? (isFirst ? "CWR" : ", CWR") : "")
          );
    */
    
    //printf( "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //printf( "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    //flags
    if(flags != option_rule->end())
    {
        std::string flags_str = flags->second;

        if((flags_str.find('F') != std::string::npos) && (tcph->fin != 0))
            printf(RED "   |-Finish Flag          : %d\n" NRM,(unsigned int)tcph->fin);
        else
            printf( "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);

        if((flags_str.find('S') != std::string::npos) && (tcph->syn != 0))
            printf(RED "   |-Synchronise Flag     : %d\n" NRM,(unsigned int)tcph->syn);
        else
            printf( "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);

        if((flags_str.find('R') != std::string::npos) && (tcph->rst != 0))
            printf(RED "   |-Reset Flag           : %d\n" NRM,(unsigned int)tcph->rst);
        else
            printf( "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);

        if((flags_str.find('P') != std::string::npos) && (tcph->psh != 0))
            printf(RED "   |-Push Flag            : %d\n" NRM,(unsigned int)tcph->psh);
        else
            printf( "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);

        if((flags_str.find('A') != std::string::npos) && (tcph->ack != 0))
            printf(RED "   |-Acknowledgement Flag : %d\n" NRM,(unsigned int)tcph->ack);
        else
            printf( "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);

        printf("\n");
    }
    else{
        printf( "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
        printf( "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
        printf( "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
        printf( "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
        printf( "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
        printf( "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
        printf("\n");
    }
         
    printf( "[TCP payload]\n");    
    
    /*
    const char *payload_ptr = (const char *) Buffer + header_size;
    std::string payload_str(payload_ptr);
    size_t pos = 0;
    std::string delimiter = " ";
    if((pos = payload_str.find(delimiter)) != std::string::npos) {
        std::string http_request  = payload_str.substr(0, pos);
         TODO: check this is valid code
        if(!http_request.compare("GET")
                || !http_request.compare("HEAD")
                || !http_request.compare("POST")
                || !http_request.compare("PUT")
                || !http_request.compare("DELETE")
                || !http_request.compare("CONNECT")
                || !http_request.compare("OPTIONS")
                || !http_request.compare("TRACE")
                || !http_request.compare("PATCH")
          )
            std::cout << "HTTP Request: " << http_request << std::endl;
    }
    */

    PrintData(Buffer + header_size , Size - header_size , option_rule);
    printf("===========================\n");
}
 
void print_udp_packet(const u_char *Buffer , int Size, std::map<std::string, std::string> *option_rule)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    printf("===========================\n");
    print_ip_header(Buffer,Size, option_rule);           
 
    printf("[UDP header]\n");
    printf("Source Port: %d\n" , ntohs(udph->source));
    printf("Destination Port: %d\n" , ntohs(udph->dest));
    printf("\n");
     
    printf("[UDP payload]\n"); 
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , Size - header_size, option_rule);
    printf("===========================\n");
}
 
void PrintData (const u_char * data , int Size, std::map<std::string, std::string> *option_rule )
{
    const char *payload = (const char *)data; 
    auto http_request = option_rule->find("http_request");
    auto content = option_rule->find("content"); 

    if(isHttpRule)
    {
        http_parse(payload);
        if(http_request != option_rule->end())
        {
            printf(RED "HTTP Request: %s %s\n" NRM, method_strings[parser->method], parsed_url.c_str()); 
        }
        else
            printf("HTTP Request: %s %s\n", method_strings[parser->method], parsed_url.c_str()); 
        

        if(content != option_rule->end())
        {
            /*
            for(int i = 0; i < Size; i++)
            {
                if(data[i]>=32 && data[i]<=128) 
                {
                    //printf( "%c",(unsigned char)data[i]);
                }
                else
                {
                    data[i] = " ";
                }
            }
            */

            std::string payload_str = std::string((const char*) data);
            std::string target_str = content->second; 
            size_t target_loc = payload_str.find(target_str);

            printf(RED "Payload: " NRM);
            for(int i = 0; i < Size; i++)
            {
                if(i < target_loc || i > target_loc + target_str.length())
                    printf("%c" , data[i]);
                else
                    printf(RED "%c" NRM, data[i]);
            }
            printf("\n");
        }
        else
        {
            printf("Payload: ");
            for(int i = 0; i < Size; i++)
            {
                if(data[i]>=32 && data[i]<=128) 
                {
                    printf( "%c",(unsigned char)data[i]);
                }
                else
                {
                    printf( " "); //CR, LF -> " " 
                }
            }
            printf("\n");
        }
        parser_free();
    }
    else
    {
        std::cout << "Payload : ";
        for(int i = 0; i < Size; i++)
        {
            if(data[i]>=32 && data[i]<=128) 
            {
                printf( "%c",(unsigned char)data[i]);
            }
            else
            {
                printf( " "); //CR, LF -> " " 
            }
        }
        printf("\n");
    } 

    /*
       int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf( "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf( "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else printf( "."); //otherwise print a dot
            }
            printf( "\n");
        } 
         
        if(i%16==0) printf( "   ");
            printf( " %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              printf( "   "); //extra spaces
            }
             
            printf( "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  printf( "%c",(unsigned char)data[j]);
                }
                else
                {
                  printf( ".");
                }
            }
             
            printf(  "\n" );
        }
    }
    */
}
/* Parse snort rules
 'alert tcp 192.168.1.0/24 any -> 192.168.1.0/24 22 (content:"/bin/sh"; msg:"Remote shell execution message! ")'
 'alert tcp any any -> 143.248.5.153 80 (msg:"A packet destined to www.kaist.ac.kr")'
 'alert udp any any -> 192.168.1.0/24 1:1024 (msg:"udp traffic from any port and destination ports ranging   from 1 to 1024")'
 'alert http any any -> any 80 (http_request:"GET"; content:"naver"; msg:"NAVER detected!")'
 */

void http_parse(const char *payload)
{
    size_t raw_len = strlen(payload);
    size_t traversed = 0;

    parser_init(HTTP_BOTH);
    traversed = http_parser_execute(parser, &settings_null, payload, raw_len);
}

bool is_http_req(const char *payload)
{
    size_t raw_len = strlen(payload);

    if(raw_len == 0)
        return false;

    size_t traversed = 0;

    parser_init(HTTP_REQUEST);
    traversed = http_parser_execute(parser, &settings_null, payload, raw_len);

    if(raw_len != traversed)
    {
        parser_free();
        return false;
    }
    parser_free();

    return true;
}

bool is_http_res(const char *payload)
{
    size_t raw_len = strlen(payload);

    if(raw_len == 0)
        return false;

    size_t traversed = 0;

    parser_init(HTTP_RESPONSE);
    traversed = http_parser_execute(parser, &settings_null, payload, raw_len);

    if(raw_len != traversed)
    {
        parser_free();
        return false;
    }
    parser_free();

    return true;
}

void parser_init (enum http_parser_type type)
{
    assert(parser == NULL);

    parser = (http_parser*)malloc(sizeof(http_parser));

    http_parser_init(parser, type);
}

void parser_free ()
{
    assert(parser);
    free(parser);
    parser = NULL;
}

int my_url_callback(http_parser* parser, const char *at, size_t length) {
    /* access to thread local custom_data_t struct.
     *   Use this access save parsed data for later use into thread local
     *     buffer, or communicate over socket
     *       */
    //parsed_url = std::string((char *)parser->data);

    parsed_url = std::string(at);

    char url[2048];
    memset(url, 0, sizeof(url));
    strncpy(url, at, length);
    parsed_url = std::string(url);
    return 0;
}



