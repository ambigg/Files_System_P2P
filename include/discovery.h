#ifndef DISCOVERY_H
#define DISCOVERY_H

#define DISCOVERY_PORT 8081
#define DISC_HELLO "P2P_HELLO"
#define DISC_ACK "P2P_ACK"

/*
 * Envía broadcast UDP anunciando este nodo.
 * Espera 2 segundos y agrega los que respondan a g_node.peers.
 * Llamar una vez al arrancar, antes de threads_start().
 */
void discovery_announce(void);

/*
 * Hilo que escucha broadcasts de otros nodos.
 * Cuando llega uno, lo agrega a peers y responde con ACK.
 */
void *thread_discovery(void *arg);

#endif
