#ifndef COMMUNICATION_H
#define COMMUNICATION_H
#include "structures.h"

int comm_send_recv(const char *ip, int port, const char *msg, char *resp,
                   int resp_len);
int comm_send(const char *ip, int port, const char *msg);
int comm_start_server(int port);
int comm_recv_from(int fd, char *buf, int max_len, char *sender_ip,
                   int *sender_port);
int comm_reply(int fd, const char *data, int len, const char *ip, int port);
int comm_broadcast(const char *msg);
void comm_close(int fd);

#endif
