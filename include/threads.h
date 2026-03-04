#ifndef THREADS_H
#define THREADS_H

/*
 * Lanza los dos hilos del nodo.
 * Llamar después de inicializar todo lo demás.
 * Retorna P2P_OK o P2P_ERR.
 */
int threads_start(void);

/*
 * Señala a ambos hilos que deben terminar.
 * No bloquea — solo pone g_node.running = 0.
 */
void threads_stop(void);

/*
 * Espera a que ambos hilos terminen (pthread_join).
 * Llamar después de threads_stop().
 */
void threads_join(void);

/* Funciones internas — no llamar directamente */
void *thread_connectivity(void *arg);
void *thread_system(void *arg);

#endif
