#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
#include <tr1/unordered_map>
#include <sys/socket.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "packet.h"
#include "multipath_connection.h"

using namespace std;

static mptcp_connection* conn = new tr1::unordered_map<string,struct TCP_conn*>();
static token *Token = new tr1::unordered_map<string,struct TCP_conn*>();
void tot_payload(struct ip_header* ip_Header,struct tcp_header* tcp_Header, char* s_ip, uint16_t s_port, char* d_ip, uint16_t d_port);
void my_packet_parser(u_char *args, const struct pcap_pkthdr* pkt_header, const u_char *bytes);
void mp_capable(struct ip_header* ip_Header,struct tcp_header* tcp_Header,struct Multipath* multipath_TCP, char* shost, uint16_t sport, char* dhost, uint16_t dport);
void mp_join(struct ip_header* ip_Header,struct tcp_header* tcp_Header,struct Multipath* multipath_TCP, char* shost, uint16_t sport, char* dhost, uint16_t dport);

//TODO: addition of SUBFLOW
int main(int argc, char **argv)
{

    FILE *input;

    //validating input parameters
    if(argc == 2)
    {
        if(!strcmp(argv[1],"r"))
        {
            input= stdin;
        }
        input = fopen(argv[1], "r");
        if(!input)
        {
            cout<< "Error in opening the file !" <<endl;
            exit(EXIT_FAILURE);
        }
    }
    if(argc != 2)
    {
        cout<<"Please input file name ! " <<endl;
        exit(EXIT_FAILURE);
    }

    //pcap lib parameters for opening the dump file
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_fopen_offline(input, errbuff);

    if(pcap == NULL)
    {
        cout<<"Error opening the dump file !"<<endl;
        exit(EXIT_FAILURE);
    }

    //loop for processing each packet one by one
    pcap_loop(pcap, 0, my_packet_parser, NULL);

    int total_conn = 0;
    typedef tr1::unordered_map<string, struct TCP_conn*> mymap;

    //printing the results
    for(mymap::iterator i= conn->begin(); i!= conn->end() ; ++i)
    {
        struct TCP_conn *loop = i->second;
        total_conn++;
        cout<<endl;
        cout<<"Host A Address : " <<loop->Clientid<<"  Token : ";
        printf("%x%x%x%x\n",loop->Clienttoken[0],loop->Clienttoken[1],loop->Clienttoken[2],loop->Clienttoken[3]);  //TODO:cout <<hex<< not working

        cout<<"Host B Address : "<< loop->Serverid<<"        Token : ";
        printf("%x%x%x%x\n",loop->Servertoken[0],loop->Servertoken[1],loop->Servertoken[2],loop->Servertoken[3]);
        cout<<"Total packets sent: " << loop->packets << endl<<"Total Bytes exchanged: " << loop->payload  <<endl;

    }
    cout<<endl<< "  ~~~~   Total Multipath TCP connections = "<< total_conn<<"    ~~~~~~~"<<endl<<endl;


    pcap_close(pcap);
    return 0;

}

void my_packet_parser(u_char *args, const struct pcap_pkthdr* packet_header, const u_char *packet)
{


    struct ethernet_header* ethernet_Header;
    struct ip_header* ip_Header;
    struct tcp_header* tcp_Header;
    ethernet_Header = (struct ethernet_header*) packet;
    ip_Header = (struct ip_header*)(packet + sizeof(struct ethernet_header));
    tcp_Header = (struct tcp_header*)(packet + sizeof(struct ethernet_header) + sizeof(struct ip_header));

    //variables to store source and destination
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;

    //variables for handling data
    u_char *data;
    int dataLength = 0;
    string dataStr = " ";

    data = (u_char*)(packet + sizeof(struct ethernet_header) + sizeof(struct ip_header) + sizeof(struct tcp_header));
    dataLength = packet_header->len - (sizeof(struct ethernet_header) + sizeof(struct ip_header) + sizeof(struct tcp_header));

    //removing packets which are not IP
    if(ntohs(ethernet_Header->ether_type) != ETHERTYPE_IP)
    {
        cout<< "Not an IP packet" << endl;
        return;
    }

    //removing packets which are not IPV4
    if(IP_V(ip_Header) != 4)
    {
        cout<<"Not an IPv4 packet" << endl;
        return;
    }


    if (ntohs(ethernet_Header->ether_type) == ETHERTYPE_IP)
    {
        inet_ntop(AF_INET, &(ip_Header->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_Header->ip_dst), destIp, INET_ADDRSTRLEN);

        if (ip_Header->ip_p == IPPROTO_TCP)
        {

            sourcePort = ntohs(tcp_Header->th_sport);
            destPort = ntohs(tcp_Header->th_dport);

            char *value = tcp_Header->options;
            char *bytes = get_tcp_payload(tcp_Header);


            while(bytes > value)
            {

                uint16_t option_type = *value;
                struct Multipath* multipath_TCP = (Multipath*) value;
                uint8_t option_subtype= multipath_TCP->subtype >> 4;

                switch(option_type)
                {
                case EOL:
                case NO:
                    value+=1;
                    break;
                case MSS:
                    value+=4;
                    break;
                case WS:
                    value+=3;
                    break;
                case SACK_P:
                    value+=2;
                    break;
                case SACK:
                    value+=*(value+1);
                    break;
                case TIMESTAMPS:
                    value+=10;
                    break;

                case MULTIPATH:

                    switch(option_subtype)
                    {
                    case MP_CAPABLE:

                        mp_capable(ip_Header, tcp_Header, multipath_TCP, sourceIp,sourcePort,destIp,destPort);

                        break;

                    case MP_JOIN:

                        mp_join(ip_Header, tcp_Header, multipath_TCP,sourceIp,sourcePort,destIp,destPort);

                        break;
                    }
                    value += *(value+1);
                    break;
                default:
                    cout<<"Packets not recognised !! Exiting"<< endl;
                    return;
                }

            }
            tot_payload(ip_Header,tcp_Header, sourceIp, sourcePort, destIp,destPort);

        }
    }
}


void mp_capable(struct ip_header* ip_Header,struct tcp_header* tcp_Header,struct Multipath* multipath_TCP, char* s_ip, uint16_t s_port, char* d_ip, uint16_t d_port)
{
    //generate connection and insert it for first message
    mptcp_conn *TCP_conn = generate_conn(s_ip, s_port, d_ip, d_port,conn);
    if(!TCP_conn)
    {
        insert_conn(s_ip, s_port, d_ip, d_port, conn);
        TCP_conn = generate_conn(s_ip, s_port, d_ip, d_port,conn);
        memcpy(TCP_conn->Clientkey, multipath_TCP->sender_key,8);

    }
    //process other messages and insert them by creating hash keys
    else
    {
        if(TCP_conn->status == SYN || TCP_conn->status == ACK )
        {

            TCP_conn->status = ESTABLISHED;
            memcpy(TCP_conn->Serverkey, multipath_TCP->sender_key, 8);
            SHA1(TCP_conn->Clientkey, 8, TCP_conn->Clienttoken);
            SHA1(TCP_conn->Serverkey, 8, TCP_conn->Servertoken);
            insert_token(TCP_conn, Token);
            insert_token(TCP_conn, Token);

        }

    }
}



void mp_join(struct ip_header* ip_Header,struct tcp_header* tcp_Header,struct Multipath* multipath_TCP, char* s_ip, uint16_t s_port, char* d_ip, uint16_t d_port)
{

    mptcp_conn *TCP_conn;
    TCP_conn = generate_conn_using_token(Token, (unsigned char *)multipath_TCP->receiver_token, d_ip, d_port);
    if(!TCP_conn)
    {
        return;
    }
    insert_conn(s_ip, s_port, d_ip, d_port, conn);

}

void tot_payload(struct ip_header* ip_Header,struct tcp_header* tcp_Header, char* s_ip, uint16_t s_port, char* d_ip, uint16_t d_port)
{
    mptcp_conn *TCP_conn = generate_conn(s_ip, s_port, d_ip, d_port,conn);
    if(TCP_conn)
    {
        TCP_conn->payload += get_ip_tot_len(ip_Header);
        TCP_conn->payload -= get_ip_len(ip_Header) * 4;
        TCP_conn->payload -= get_tcp_data_offset(tcp_Header) * 4;
        TCP_conn->packets++;
    }

}
