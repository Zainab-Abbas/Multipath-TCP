#include "multipath_connection.h"
#include <tr1/unordered_map>
using namespace std;


mptcp_conn *generate_conn(char* s_ip, uint16_t s_port, char* d_ip, uint16_t d_port,mptcp_connection *unordered_map)
{
    char id_no1[41];
    char id_no2[41];
    sprintf(id_no1, "%s%u", s_ip, d_port);
    sprintf(id_no2, "%s%u", d_ip, s_port);
    if(unordered_map->count(id_no1))
        return unordered_map->find(id_no1)->second;
    if(unordered_map->count(id_no2))
        return unordered_map->find(id_no2)->second;
    return NULL;
}

void insert_conn(char* s_ip, uint16_t s_port, char* d_ip, uint16_t d_port, mptcp_connection *unordered_map)
{

    char conn_id[41];
    mptcp_conn *TCP_conn = new(mptcp_conn);
    sprintf(TCP_conn->Clientid, "%s:%u", s_ip, s_port);
    sprintf(TCP_conn->Serverid, "%s:%u", d_ip, d_port);
    unordered_map->insert(pair<char*,struct TCP_conn*>(conn_id, TCP_conn));
}

void insert_token(mptcp_conn *TCP_conn, token *unordered_map)
{

    char Servertoken[41];
    char Clienttoken[41];
    sprintf(Servertoken, "%x",TCP_conn->Servertoken[0]);
    sprintf(Clienttoken, "%x",TCP_conn->Clienttoken[0]);
    unordered_map->insert(pair<char*,struct TCP_conn*>(Servertoken, TCP_conn));
    unordered_map->insert(pair<char*,struct TCP_conn*>(Clienttoken, TCP_conn));

}

mptcp_conn *generate_conn_using_token(token *unordered_map, unsigned char *token, char *host, uint16_t port)
{

    char Id[41];
    sprintf(Id, "%x", token[0]);
    if(unordered_map->count(Id))
        return unordered_map->find(Id)->second;
    return NULL;

}


