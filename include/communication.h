#ifndef COMMUNICATION_H
#define COMMUNICATION_H
#include "structures.h"

/* Send a message and wait for response. Returns P2P_OK, P2P_TIMEOUT or P2P_ERR
 */
int comm_send_recv(const char *ip, int port, const char *msg, char *resp,
                   int resp_len);

/* Send without waiting for response */
int comm_send(const char *ip, int port, const char *msg);

/* Create UDP server socket bound to port. Returns fd or -1 */
int comm_start_server(int port);

/* Receive a datagram. Fills sender_ip and sender_port. Returns bytes or <=0 */
int comm_recv_from(int fd, char *buf, int max_len, char *sender_ip,
                   int *sender_port);

/* Send response back using server fd to exact sender address */
int comm_reply(int fd, const char *data, int len, const char *ip, int port);

/* Broadcast to all peers */
int comm_broadcast(const char *msg);

void comm_close(int fd);

#endif
