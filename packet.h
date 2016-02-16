#include <stdint.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>

#define ETHERNET_SIZE 14
#define ETHERNET_ADDR_LEN 6

typedef struct ethernet_header
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
} ethernet_Header;


typedef struct ip_header
{
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    u_int ip_src,ip_dst; /* source and dest address */
    char options[0];
} ip_Header;
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)


uint16_t get_ip_tot_len(ip_Header*);    /*   get total length   */
uint8_t get_ip_len(ip_Header*);        /* get length     */
void *get_ip_payload(ip_Header*);

typedef struct tcp_header
{
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t th_offset;
    uint8_t th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
    char options[];
} tcp_Header;


enum tcp_value
{
    EOL        = 0,
    NO         = 1,
    MSS        = 2,
    WS         = 3,
    SACK_P     = 4,
    SACK       = 5,
    TIMESTAMPS = 8,
    MULTIPATH  = 30,
};

uint8_t get_tcp_data_offset(tcp_Header*);
char *get_tcp_payload(tcp_Header*);

typedef struct Multipath
{
    uint8_t kind;
    uint8_t length;
    uint8_t subtype;
    uint8_t flags;
    uint32_t hmac;
    char sender_key[8];
    char receiver_key[8];
    struct in_addr address;
    unsigned char receiver_token[4];
    unsigned char sender_randomno[4];
    char payload[0];
} multipath_TCP;


enum multipath_value
{
    MP_CAPABLE   = 0,
    MP_JOIN      = 1,
    DSS          = 2,
    ADD_ADDR     = 3,
    REMOVE_ADDR  = 4,
    MP_PRIO      = 5,
    MP_FAIL      = 6,
    MP_FASTCLOSE = 7,
};

