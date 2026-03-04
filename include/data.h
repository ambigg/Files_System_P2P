#ifndef DATA_H
#define DATA_H

#include "structures.h"

/*
 * Lee un archivo completo en memoria.
 * El buffer se reserva con malloc — el caller debe liberar con free().
 * size_out : tamaño del archivo en bytes
 * Retorna puntero al contenido, NULL en error.
 */
unsigned char *data_read_file(const char *path, long *size_out);

/*
 * Escribe contenido en un archivo.
 * Crea el archivo si no existe, lo sobreescribe si existe.
 * Retorna P2P_OK o P2P_ERR.
 */
int data_write_file(const char *path, const unsigned char *content, long size);

/*
 * Llena una FileEntry con los metadatos de un archivo real en disco.
 * Retorna P2P_OK o P2P_ERR si el archivo no existe.
 */
int data_stat_file(const char *path, FileEntry *out);

/*
 * Carga la lista de peers desde peers.conf.
 * Formato del archivo: IP:PUERTO  (uno por línea, # para comentarios)
 * Retorna número de peers cargados.
 */
int data_load_peers(const char *conf_path, PeerNode *peers, int max);

/*
 * Guarda LISTA_OWN en files.txt.
 * Retorna P2P_OK o P2P_ERR.
 */
int data_save_own_list(const char *path, const FileEntry *files, int count);

/*
 * Carga LISTA_OWN desde files.txt.
 * Retorna número de entradas cargadas.
 */
int data_load_own_list(const char *path, FileEntry *files, int max);

/*
 * Crea una copia temporal de un archivo remoto en tmp/.
 * Nombre del archivo temporal: tmp/NOMBRE__IP_DEL_DUEÑO.tmp
 * temp_path_out : buffer de MAX_PATH_LEN donde se escribe la ruta
 * Retorna P2P_OK o P2P_ERR.
 */
int data_create_temp_copy(const char *filename, const char *owner_ip,
                          const unsigned char *content, long size,
                          char *temp_path_out);

/*
 * Elimina un archivo temporal.
 */
void data_delete_temp(const char *temp_path);

/*
 * Extrae la extensión de un nombre de archivo.
 * "reporte.txt" → "txt"
 * "foto"        → ""   (sin extensión)
 */
void data_get_extension(const char *filename, char *ext_out);

#endif
