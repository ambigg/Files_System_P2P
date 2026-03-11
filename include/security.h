#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>

/*
 * Clave compartida — todos los nodos deben tener la misma.
 * En una implementación real esto vendría de un archivo de config.
 */
#define SEC_SHARED_KEY "p2pFS_key_2026"
#define SEC_KEY_LEN 16

/*
 * Cifra un mensaje de texto claro y construye el envelope seguro.
 *
 *   plaintext → SEC|IV_HEX|MSG_CIFRADO_HEX|CRC32_HEX\n
 *
 * out necesita al menos plain_len*2 + 64 bytes.
 * Retorna longitud del mensaje seguro, -1 en error.
 */
int sec_encrypt(const char *plaintext, int plain_len, char *out);

/*
 * Descifra un envelope seguro y devuelve el texto claro.
 *
 *   SEC|IV_HEX|MSG_CIFRADO_HEX|CRC32_HEX\n → plaintext
 *
 * Retorna P2P_OK si la integridad es válida.
 * Retorna P2P_AUTH_FAIL si el CRC32 no coincide (mensaje alterado).
 * Retorna P2P_ERR si el formato es inválido.
 */
int sec_decrypt(const char *secure_msg, char *out, int *out_len);

/*
 * Calcula el CRC32 de un buffer.
 * Usado internamente y también disponible para tests.
 */
uint32_t sec_crc32(const unsigned char *data, int len);

/*
 * Verifica si un mensaje tiene el formato seguro.
 * Retorna 1 si empieza con "SEC|", 0 si no.
 */
int sec_is_secure(const char *msg);

/* Utilidades de conversión hex — usadas internamente */
void sec_bytes_to_hex(const unsigned char *bytes, int len, char *hex_out);
int sec_hex_to_bytes(const char *hex, unsigned char *bytes_out);

#endif
