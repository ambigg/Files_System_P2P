#ifndef TRANSFER_H
#define TRANSFER_H

#include "structures.h"

/* =========================================================
 * CONSTRUCCIÓN DE MENSAJES
 * Todas devuelven la longitud del mensaje, -1 en error.
 * out necesita al menos MAX_MSG_LEN bytes.
 * ========================================================= */

int transfer_build_get_list(char *out, const char *sender_ip);

int transfer_build_list_resp(char *out, const char *sender_ip,
                             const FileEntry *files, int count);

int transfer_build_get_info(char *out, const char *sender_ip,
                            const char *filename);

int transfer_build_info_resp(char *out, const char *sender_ip,
                             const FileEntry *entry);

int transfer_build_info_redir(char *out, const char *sender_ip,
                              const char *filename, const char *owner_ip);

int transfer_build_get_file(char *out, const char *sender_ip,
                            const char *filename);

int transfer_build_file_resp(char *out, const char *sender_ip,
                             const char *filename, const unsigned char *content,
                             long size);

int transfer_build_new_file(char *out, const char *sender_ip,
                            const FileEntry *entry);

int transfer_build_sync_file(char *out, const char *sender_ip,
                             const char *filename, const unsigned char *content,
                             long size, time_t mod_time);

int transfer_build_nack(char *out, const char *sender_ip, const char *filename);

int transfer_build_ack(char *out, const char *sender_ip, const char *info);

/* =========================================================
 * PARSING DE MENSAJES
 * ========================================================= */

/* Parsea un mensaje crudo en una estructura Message.
 * Retorna P2P_OK o P2P_ERR si el formato es inválido. */
int transfer_parse_message(const char *raw, Message *msg);

/* Parsea el payload de LIST_RESP.
 * Retorna número de entradas parseadas, -1 en error. */
int transfer_parse_list_payload(const char *payload, FileEntry *files,
                                int max_files);

/* Parsea el payload de INFO_RESP.
 * Retorna P2P_OK o P2P_ERR. */
int transfer_parse_info_payload(const char *payload, FileEntry *entry);

/* Parsea el payload de FILE_RESP.
 * filename_out : buffer de MAX_FILENAME_LEN
 * content_out  : buffer suficientemente grande (MAX_PAYLOAD_LEN)
 * size_out     : tamaño real del contenido decodificado
 * Retorna P2P_OK o P2P_ERR. */
int transfer_parse_file_payload(const char *payload, char *filename_out,
                                unsigned char *content_out, long *size_out);

/* =========================================================
 * BASE64
 * ========================================================= */

/* Retorna longitud del string generado. */
int transfer_base64_encode(const unsigned char *input, long input_len,
                           char *output);

/* Retorna P2P_OK o P2P_ERR. */
int transfer_base64_decode(const char *input, unsigned char *output,
                           long *output_len);

#endif
