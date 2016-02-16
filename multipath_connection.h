#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tr1/unordered_map>
#include <string>
#include <vector>

using namespace std;

enum conn_status
{
    SYN,
    ACK,
    ESTABLISHED,
    FIN,
};

typedef struct TCP_conn
{
    char Clientid[21];
    char Serverid[21];
    u_char Clientkey[8];
    u_char Serverkey[8];
    u_char Clienttoken[20];
    u_char Servertoken[20];
    conn_status status;
    vector<struct TCP_conn*> subflow_list;//TODO
    u_int packets;
    u_int payload;
} mptcp_conn;


typedef tr1::unordered_map<string, struct TCP_conn*> mptcp_connection;
typedef tr1::unordered_map<string, struct TCP_conn*> token;


void insert_conn(char* s_ip, uint16_t s_port, char* d_ip, uint16_t d_port, mptcp_connection *unordered_map);
mptcp_conn *generate_conn(char* s_ip, uint16_t s_port, char* d_ip, uint16_t d_port,mptcp_connection *unordered_map);
void insert_token(mptcp_conn *TCP_conn, token *unordered_map);
mptcp_conn *generate_conn_using_token(token *unordered_map, unsigned char *token, char *host, uint16_t port);

