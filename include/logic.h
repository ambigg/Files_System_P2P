#ifndef LOGIC_H
#define LOGIC_H

#include "structures.h"

/* ==========================================================
 * SERVIDOR — maneja peticiones entrantes de otros nodos
 * ========================================================== */

/*
 * Punto de entrada principal del servidor.
 * Recibe un mensaje ya parseado de un peer y genera la respuesta.
 *
 * msg        : mensaje recibido (ya descifrado y parseado)
 * sender_ip  : IP de quien envió el mensaje
 * response   : buffer de salida con el mensaje de respuesta
 *              en texto plano — la capa de comunicación lo
 *              cifrará antes de enviarlo
 *
 * Retorna P2P_OK, P2P_NOT_FOUND o P2P_ERR.
 */
int logic_handle_request(const Message *msg, const char *sender_ip,
                         char *response);

/* ==========================================================
 * CLIENTE — operaciones iniciadas por el usuario
 * ========================================================== */

/*
 * Busca información de un archivo en la red.
 * Primero mira LISTA_OWN, luego LISTA_GENERAL,
 * luego pregunta a los peers si hace falta.
 *
 * entry_out : se llena con los atributos del archivo
 * Retorna P2P_OK o P2P_NOT_FOUND.
 */
int logic_get_file_info(const char *filename, FileEntry *entry_out);

/*
 * Abre un archivo para uso.
 * Si es local: devuelve la ruta directa en shared/.
 * Si es remoto: pide copia al dueño, la guarda en tmp/,
 *               registra el lease.
 *
 * local_path_out : ruta del archivo listo para usar
 * Retorna P2P_OK, P2P_NOT_FOUND o P2P_ERR.
 */
int logic_open_file(const char *filename, char *local_path_out);

/*
 * Cierra un archivo en uso.
 * Si hubo cambios: envía SYNC_FILE al dueño.
 * Si no hubo cambios: no envía nada.
 * En cualquier caso: elimina la copia temporal y libera el lease.
 *
 * local_path : ruta del archivo temporal (de logic_open_file)
 * Retorna P2P_OK o P2P_ERR.
 */
int logic_close_file(const char *local_path);

/*
 * Marca un lease como modificado.
 * Llamar desde la capa de presentación cuando el usuario
 * guarda cambios en el editor.
 */
void logic_mark_modified(const char *local_path);

/* ==========================================================
 * NOTIFICACIONES
 * ========================================================== */

/*
 * Procesa la llegada de un NEW_FILE de un peer.
 * Agrega la entrada a LISTA_GENERAL y escribe en el log.
 */
void logic_handle_new_file(const FileEntry *entry, const char *from_ip);

/*
 * Anuncia un archivo propio nuevo a todos los peers.
 * Construye NEW_FILE, lo cifra y hace broadcast.
 */
void logic_announce_new_file(const FileEntry *entry);

#endif
