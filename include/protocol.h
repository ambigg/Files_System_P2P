#ifndef PROTOCOL_H
#define PROTOCOL_H

#define P2P_PORT 8080
#define MAX_IP_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_PATH_LEN 512
#define MAX_MSG_LEN 65536
#define MAX_PAYLOAD_LEN (MAX_MSG_LEN - 128)
#define MAX_PEERS 64
#define MAX_FILES 1024
#define TTL_PERMANENT 0
#define UPDATE_INTERVAL 10
#define CONN_TIMEOUT 3

/* Separadores del protocolo */
#define FIELD_SEP '|'
#define FIELD_SEP_STR "|"
#define RECORD_SEP ';'
#define ATTR_SEP ','
#define ATTR_SEP_STR ","

/* Tipos de mensaje */
#define MSG_GET_LIST "GET_LIST"
#define MSG_LIST_RESP "LIST_RESP"
#define MSG_GET_INFO "GET_INFO"
#define MSG_INFO_RESP "INFO_RESP"
#define MSG_INFO_REDIR "INFO_REDIR"
#define MSG_GET_FILE "GET_FILE"
#define MSG_FILE_RESP "FILE_RESP"
#define MSG_NEW_FILE "NEW_FILE"
#define MSG_SYNC_FILE "SYNC_FILE"
#define MSG_NACK "NACK"
#define MSG_ACK "ACK"
#define MSG_SECURE "SEC"

/* Códigos de retorno */
#define P2P_OK 0
#define P2P_ERR -1
#define P2P_NOT_FOUND -2
#define P2P_TIMEOUT -3
#define P2P_AUTH_FAIL -4

#endif
