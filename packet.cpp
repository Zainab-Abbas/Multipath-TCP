#include "packet.h"


uint8_t get_ip_len(ip_Header* header)
{
    return header->ip_len;
}


uint16_t get_ip_tot_len(ip_Header* header)
{
    return ntohs(header->ip_len);
}


void *get_ip_payload(ip_Header* header)
{
    return (void *) ((uint32_t*) header + get_ip_len(header));
}

char *get_tcp_payload(tcp_Header* header)
{
    return (char *) ((uint32_t*) header + get_tcp_data_offset(header));
}
uint8_t get_tcp_data_offset(tcp_Header* header)
{
    return (header->th_offset >> 4);
}

