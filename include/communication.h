#ifndef COMMUNICATION_H
#define COMMUNICATION_H
#include "structures.h"

/* Send message and wait for UDP response */
int comm_send_recv(const char *ip, int port, const char *message,
                   char *response, int resp_len);

/* Send UDP datagram, no response expected */
int comm_send(const char *ip, int port, const char *message);

/* Bind UDP socket to port — returns fd, -1 on error */
int comm_start_server(int port);

/* Receive one datagram. Fills sender_ip and sender_port. */
int comm_recv(int server_fd, char *buffer, int max_len, char *sender_ip,
              int *sender_port);

/* Send response back via the server socket */
int comm_send_to(int server_fd, const char *data, int len, const char *ip,
                 int port);

void comm_close(int fd);

/* Send to every peer in g_node.peers */
int comm_broadcast(const char *message);

#endif
