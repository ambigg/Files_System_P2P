#ifndef DIRECTORY_H
#define DIRECTORY_H

#include "structures.h"

/* ==========================================================
 * INICIALIZACIÓN
 * ========================================================== */

/*
 * Inicializa los mutexes de ambas listas.
 * Llamar una sola vez al arrancar, antes de crear los hilos.
 */
void dir_init(void);

/* ==========================================================
 * LISTA_OWN
 * ========================================================== */

/*
 * Escanea la carpeta shared/ y reconstruye LISTA_OWN desde cero.
 * Usa data_stat_file() para obtener metadatos de cada archivo.
 */
void dir_scan_own(void);

/*
 * Carga LISTA_OWN desde files.txt en disco.
 * Útil al arrancar si ya existía una lista guardada.
 */
void dir_load_own(void);

/*
 * Persiste LISTA_OWN en files.txt.
 * Llamar después de cada cambio en la lista propia.
 */
void dir_save_own(void);

/*
 * Agrega o actualiza una entrada en LISTA_OWN.
 * Si ya existe un archivo con el mismo nombre, lo reemplaza.
 */
void dir_own_add(const FileEntry *entry);

/*
 * Elimina una entrada de LISTA_OWN por nombre.
 */
void dir_own_remove(const char *filename);

/*
 * Copia LISTA_OWN a un arreglo externo (thread-safe).
 * out : buffer con capacidad para max entradas.
 * Retorna número de entradas copiadas.
 */
int dir_own_snapshot(FileEntry *out, int max);

/* ==========================================================
 * LISTA_GENERAL
 * ========================================================== */

/*
 * Actualiza LISTA_GENERAL con la lista recibida de un peer.
 * Primero borra todas las entradas de ese peer,
 * luego inserta las nuevas. Maneja automáticamente
 * archivos que el peer dejó de compartir.
 */
void dir_general_update_from_peer(const char *peer_ip, const FileEntry *files,
                                  int count);

/*
 * Elimina todos los archivos de un peer de LISTA_GENERAL.
 * Se llama cuando un peer no responde (se cayó).
 */
void dir_general_remove_peer(const char *peer_ip);

/*
 * Agrega o actualiza una sola entrada en LISTA_GENERAL.
 * Se usa cuando llega una notificación NEW_FILE.
 */
void dir_general_add(const FileEntry *entry);

/*
 * Busca un archivo en LISTA_OWN y LISTA_GENERAL.
 * Llena found_out con los datos si lo encuentra.
 * Retorna P2P_OK si encontró, P2P_NOT_FOUND si no.
 * Toma y libera los mutexes internamente.
 */
int dir_find(const char *filename, FileEntry *found_out);

/*
 * Copia LISTA_GENERAL + LISTA_OWN a un arreglo (thread-safe).
 * Retorna número total de entradas copiadas.
 */
int dir_general_snapshot(FileEntry *out, int max);

/*
 * Persiste LISTA_GENERAL en config/general.txt.
 * Llamar al final de cada update_all_lists() para que
 * el directorio de red sobreviva reinicios del nodo.
 */
void dir_save_general(void);

/*
 * Carga LISTA_GENERAL desde config/general.txt.
 * Llamar al arrancar, después de dir_load_own(),
 * para tener el último estado conocido de la red
 * antes de que los peers respondan.
 */
void dir_load_general(void);

/*
 * Decrementa el TTL de cada entrada de LISTA_GENERAL.
 * Las entradas con TTL=0 (permanentes) no se tocan.
 * Las que llegan a TTL<=0 se copian a expired_out y se eliminan.
 * Retorna número de entradas expiradas.
 */
int dir_tick_ttl(FileEntry *expired_out, int max);

#endif
