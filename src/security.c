#include "../include/security.h"
#include "../include/log.h"
#include "../include/protocol.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ==========================================================
 * CRC32
 * Standard table with polynomial 0xEDB88320.
 * Same algorithm used by zlib — can be verified with any
 * online CRC32 calculator.
 * ========================================================== */

static uint32_t crc32_table[256];
static int crc32_ready = 0;

static void crc32_build_table(void) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int j = 0; j < 8; j++)
      c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
    crc32_table[i] = c;
  }
  crc32_ready = 1;
}

uint32_t sec_crc32(const unsigned char *data, int len) {
  if (!crc32_ready)
    crc32_build_table();

  uint32_t crc = 0xFFFFFFFF;
  for (int i = 0; i < len; i++)
    crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
  return crc ^ 0xFFFFFFFF;
}

/* ==========================================================
 * HEX CONVERSION
 * ========================================================== */

void sec_bytes_to_hex(const unsigned char *bytes, int len, char *hex_out) {
  for (int i = 0; i < len; i++)
    sprintf(hex_out + i * 2, "%02x", bytes[i]);
  hex_out[len * 2] = '\0';
}

int sec_hex_to_bytes(const char *hex, unsigned char *bytes_out) {
  int len = strlen(hex);
  if (len % 2 != 0)
    return -1;

  for (int i = 0; i < len; i += 2) {
    unsigned int byte;
    if (sscanf(hex + i, "%02x", &byte) != 1)
      return -1;
    bytes_out[i / 2] = (unsigned char)byte;
  }
  return len / 2;
}

/* ==========================================================
 * XOR ENCRYPTION WITH IV
 *
 * For each byte i of the message:
 *   effective_key = KEY[i % KEY_LEN] XOR IV[i % 4]
 *   cipher_byte   = plain_byte XOR effective_key
 *
 * The same code encrypts and decrypts (XOR is symmetric).
 * The random IV makes the same message produce a different
 * ciphertext each time.
 * ========================================================== */

static void xor_cipher(const unsigned char *in, int len,
                       const unsigned char *iv, unsigned char *out) {
  const char *key = SEC_SHARED_KEY;
  int key_len = strlen(key);

  for (int i = 0; i < len; i++) {
    unsigned char k = (unsigned char)key[i % key_len] ^ iv[i % 4];
    out[i] = in[i] ^ k;
  }
}

/* ==========================================================
 * ENCRYPT
 *
 * Flow:
 *   1. Generate a random 4‑byte IV
 *   2. Compute CRC32 of the original plaintext
 *   3. Encrypt with XOR+IV
 *   4. Convert IV, cipher and CRC to hex
 *   5. Build: SEC|IV_HEX|CIPHER_HEX|CRC_HEX\n
 * ========================================================== */

int sec_encrypt(const char *plaintext, int plain_len, char *out) {
  if (!plaintext || plain_len <= 0 || !out)
    return -1;

  /* 4‑byte random IV */
  srand((unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)plaintext);
  unsigned char iv[4];
  for (int i = 0; i < 4; i++)
    iv[i] = (unsigned char)(rand() & 0xFF);

  /* CRC32 of the original plaintext (before encryption) */
  uint32_t crc = sec_crc32((const unsigned char *)plaintext, plain_len);
  unsigned char crc_b[4] = {(crc >> 24) & 0xFF, (crc >> 16) & 0xFF,
                            (crc >> 8) & 0xFF, crc & 0xFF};

  /* Encrypt */
  unsigned char *cipher = malloc(plain_len);
  if (!cipher)
    return -1;
  xor_cipher((const unsigned char *)plaintext, plain_len, iv, cipher);

  /* To hex */
  char iv_hex[9]; /* 4 bytes = 8 chars + \0 */
  char crc_hex[9];
  char *cipher_hex = malloc(plain_len * 2 + 1);
  if (!cipher_hex) {
    free(cipher);
    return -1;
  }

  sec_bytes_to_hex(iv, 4, iv_hex);
  sec_bytes_to_hex(crc_b, 4, crc_hex);
  sec_bytes_to_hex(cipher, plain_len, cipher_hex);

  /* Build secure message */
  int n = snprintf(out, MAX_MSG_LEN, "%s%c%s%c%s%c%s\n", MSG_SECURE, FIELD_SEP,
                   iv_hex, FIELD_SEP, cipher_hex, FIELD_SEP, crc_hex);

  free(cipher);
  free(cipher_hex);

  if (n >= MAX_MSG_LEN) {
    LOG_E("SECURITY", "Message too large to encrypt");
    return -1;
  }

  LOG_N("SECURITY", "ENCRYPT OK: %d bytes → %d bytes (IV=%s)", plain_len, n,
        iv_hex);
  return n;
}

/* ==========================================================
 * DECRYPT
 *
 * Flow:
 *   1. Check that it starts with "SEC"
 *   2. Extract IV_HEX, CIPHER_HEX, CRC_HEX
 *   3. Convert from hex to bytes
 *   4. Decrypt with XOR+IV (same code as encryption)
 *   5. Compute CRC32 of the result
 *   6. Compare with received CRC32 — if different: tampering
 * ========================================================== */

int sec_decrypt(const char *secure_msg, char *out, int *out_len) {
  if (!secure_msg || !out || !out_len)
    return P2P_ERR;

  char buf[MAX_MSG_LEN];
  strncpy(buf, secure_msg, MAX_MSG_LEN - 1);
  buf[MAX_MSG_LEN - 1] = '\0';

  /* Remove trailing '\n' */
  int len = strlen(buf);
  if (len > 0 && buf[len - 1] == '\n')
    buf[--len] = '\0';

  char *rest = buf;
  char *tok;

  /* Check "SEC" */
  tok = strsep(&rest, "|");
  if (!tok || strcmp(tok, MSG_SECURE) != 0) {
    LOG_E("SECURITY", "DECRYPT: not a secure message");
    return P2P_ERR;
  }

  /* IV hex → bytes */
  tok = strsep(&rest, "|");
  if (!tok || strlen(tok) != 8) {
    LOG_E("SECURITY", "DECRYPT: invalid IV");
    return P2P_ERR;
  }
  unsigned char iv[4];
  if (sec_hex_to_bytes(tok, iv) != 4)
    return P2P_ERR;

  /* Cipher hex → bytes */
  tok = strsep(&rest, "|");
  if (!tok) {
    LOG_E("SECURITY", "DECRYPT: missing cipher");
    return P2P_ERR;
  }
  int cipher_len = strlen(tok) / 2;
  if (strlen(tok) % 2 != 0)
    return P2P_ERR;

  unsigned char *cipher = malloc(cipher_len);
  if (!cipher)
    return P2P_ERR;
  if (sec_hex_to_bytes(tok, cipher) != cipher_len) {
    free(cipher);
    return P2P_ERR;
  }

  /* CRC hex → value */
  tok = strsep(&rest, "|");
  if (!tok || strlen(tok) != 8) {
    free(cipher);
    LOG_E("SECURITY", "DECRYPT: invalid CRC");
    return P2P_ERR;
  }
  unsigned char crc_b[4];
  if (sec_hex_to_bytes(tok, crc_b) != 4) {
    free(cipher);
    return P2P_ERR;
  }

  uint32_t expected_crc = ((uint32_t)crc_b[0] << 24) |
                          ((uint32_t)crc_b[1] << 16) |
                          ((uint32_t)crc_b[2] << 8) | (uint32_t)crc_b[3];

  /* Decrypt (XOR is its own inverse) */
  unsigned char *plain = malloc(cipher_len + 1);
  if (!plain) {
    free(cipher);
    return P2P_ERR;
  }
  xor_cipher(cipher, cipher_len, iv, plain);
  plain[cipher_len] = '\0';
  free(cipher);

  /* Verify integrity */
  uint32_t actual_crc = sec_crc32(plain, cipher_len);
  if (actual_crc != expected_crc) {
    free(plain);
    LOG_E("SECURITY",
          "DECRYPT: CRC mismatch (expected=%08x actual=%08x) "
          "— message discarded",
          expected_crc, actual_crc);
    return P2P_AUTH_FAIL;
  }

  memcpy(out, plain, cipher_len);
  out[cipher_len] = '\0';
  *out_len = cipher_len;
  free(plain);

  LOG_N("SECURITY", "DECRYPT OK: %d bytes", cipher_len);
  return P2P_OK;
}

/* ==========================================================
 * DETECT SECURE MESSAGE
 * ========================================================== */

int sec_is_secure(const char *msg) {
  return (msg && strncmp(msg, "SEC|", 4) == 0);
}
