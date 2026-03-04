#ifndef PRESENTATION_H
#define PRESENTATION_H

/*
 * Loop principal de la UI.
 * Bloquea hasta que el usuario elige salir.
 * Llamar desde main() después de inicializar todo.
 */
void presentation_run(void);

/* Muestra todos los archivos de la red (LISTA_GENERAL + OWN) */
void presentation_show_directory(void);

/* Muestra los atributos de un archivo específico */
void presentation_show_file_info(const char *filename);

/*
 * Abre un archivo para ver y editar.
 * Transparente: el usuario no sabe si es local o remoto.
 */
void presentation_open_file(const char *filename);

/* Muestra los peers conocidos y su estado online/offline */
void presentation_show_peers(void);

#endif
