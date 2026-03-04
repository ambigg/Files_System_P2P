#ifndef LOG_H
#define LOG_H

typedef enum {
  LOG_INFO = 0,
  LOG_WARN,
  LOG_ERROR,
  LOG_NET,  /* operaciones de red */
  LOG_DIR,  /* cambios en listas */
  LOG_FILE, /* operaciones de archivo */
  LOG_SEC,  /* seguridad */
} LogLevel;

/*
 * Inicializa el log. Llamar una vez al arrancar.
 * log_path : ruta al archivo  (ej: "logs/192_168_1_10.log")
 * my_ip    : IP de este nodo, se imprime en cada línea
 */
void log_init(const char *log_path, const char *my_ip);

/*
 * Escribe una entrada. Formato:
 * [YYYY-MM-DD HH:MM:SS] [NIVEL] [IP_NODO] [MODULO] mensaje
 */
void log_write(LogLevel level, const char *module, const char *fmt, ...);

void log_close(void);

/* Macros para no escribir log_write(LOG_INFO, ...) todo el tiempo */
#define LOG_I(mod, ...) log_write(LOG_INFO, mod, __VA_ARGS__)
#define LOG_W(mod, ...) log_write(LOG_WARN, mod, __VA_ARGS__)
#define LOG_E(mod, ...) log_write(LOG_ERROR, mod, __VA_ARGS__)
#define LOG_N(mod, ...) log_write(LOG_NET, mod, __VA_ARGS__)
#define LOG_D(mod, ...) log_write(LOG_DIR, mod, __VA_ARGS__)
#define LOG_F(mod, ...) log_write(LOG_FILE, mod, __VA_ARGS__)

#endif
