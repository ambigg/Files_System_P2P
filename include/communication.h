#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include "structures.h"

/* Timeout en segundos para operaciones de socket */
#define COMM_TIMEOUT_SEC 5

/*
 * Envía un mensaje a un peer y espera su respuesta.
 * ip       : IP destino
 * port     : puerto destino
 * message  : string a enviar (ya cifrado por capa 3)
 * response : buffer donde se guarda la respuesta (MAX_MSG_LEN)
 * resp_len : tamaño del buffer de respuesta
 *
 * Retorna P2P_OK, P2P_TIMEOUT o P2P_ERR.
 */
int comm_send_recv(const char *ip, int port, const char *message,
                   char *response, int resp_len);

/*
 * Envía un mensaje sin esperar respuesta.
 * Útil para broadcasts y notificaciones.
 *
 * Retorna P2P_OK o P2P_ERR.
 */
int comm_send(const char *ip, int port, const char *message);

/*
 * Inicia el servidor TCP: socket + bind + listen.
 * Retorna el file descriptor del servidor, -1 en error.
 */
int comm_start_server(int port);

/*
 * Acepta una conexión entrante (bloqueante).
 * server_fd : fd del servidor
 * client_ip : buffer donde se guarda la IP del cliente (MAX_IP_LEN)
 *
 * Retorna fd del cliente, -1 en error o timeout.
 */
int comm_accept(int server_fd, char *client_ip);

/*
 * Lee un mensaje completo de un fd (hasta '\n').
 * Retorna bytes leídos, 0 si cerró la conexión, -1 en error.
 */
int comm_recv(int fd, char *buffer, int max_len);

/*
 * Escribe datos en un fd ya abierto.
 * Retorna P2P_OK o P2P_ERR.
 */
int comm_send_fd(int fd, const char *data, int len);

/*
 * Cierra un fd.
 */
void comm_close(int fd);

/*
 * Envía un mensaje a todos los peers marcados como reachable.
 * Usa g_node.peers internamente.
 * Retorna cuántos peers recibieron el mensaje.
 */
int comm_broadcast(const char *message);

/*
 * Verifica si un peer está disponible (connect rápido + close).
 * Retorna 1 si online, 0 si no responde.
 */
int comm_ping(const char *ip, int port);

#endif
