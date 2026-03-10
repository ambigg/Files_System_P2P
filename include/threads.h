#ifndef THREADS_H
#define THREADS_H

/* Start the 2 threads (connectivity + system). */
int threads_start(void);

/* Signal threads to stop (sets g_node.running = 0). */
void threads_stop(void);

/* Wait for both threads to finish. */
void threads_join(void);

/* Ask every peer in peers.conf for their list right now.
 * Called on demand from presentation (option 1 and 5). */
void update_all_lists(void);

/* Internal thread functions */
void *thread_connectivity(void *arg);
void *thread_system(void *arg);

#endif
