# ============================================================
# Makefile 
# ============================================================

CC      = gcc
CFLAGS  = -Wall -Wextra -Iinclude -pthread -g
LDFLAGS = -pthread
TARGET  = p2p_node

SRCS =  src/main.c          \
        src/log.c           \
        src/transfer.c      \
        src/security.c      \
        src/communication.c \
        src/data.c          \
        src/directory.c     \
        src/logic.c         \
        src/threads.c       \
        src/presentation.c  \
        src/discovery.c

OBJS = $(SRCS:.c=.o)

# ── Build principal ──────────────────────────────────────────
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo ""
	@echo "  ✓ Compilado: $(TARGET)"
	@echo "  Uso: ./$(TARGET) <ip> [puerto]"
	@echo ""

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ── Tests unitarios ──────────────────────────────────────────
#
# Cada test compila solo las capas que necesita,
# sin main.c ni capas de red, para poder correrlos
# en cualquier máquina sin peers configurados.

test_transfer: src/transfer.c src/log.c tests/test_transfer.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "  ✓ test_transfer compilado"

test_security: src/security.c src/log.c tests/test_security.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "  ✓ test_security compilado"

test_data: src/data.c src/log.c tests/test_data.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "  ✓ test_data compilado"

tests: test_transfer test_security test_data
	@echo ""
	@echo "  Corriendo tests..."
	@echo ""
	./test_transfer
	./test_security
	./test_data

# ── Limpieza ─────────────────────────────────────────────────
clean:
	rm -f $(OBJS) $(TARGET)
	rm -f test_transfer test_security test_data

clean_run:
	rm -f logs/*.log
	rm -f tmp/*.tmp
	rm -f config/files.txt

clean_all: clean clean_run

# ── Ayuda ────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  make              compilar el nodo"
	@echo "  make tests        compilar y correr tests"
	@echo "  make clean        borrar binarios y objetos"
	@echo "  make clean_run    borrar logs, temporales y lista"
	@echo "  make clean_all    todo lo anterior"
	@echo ""
	@echo "  Correr un nodo:"
	@echo "    ./p2p_node 192.168.1.10"
	@echo "    ./p2p_node 192.168.1.10 9090"
	@echo ""

.PHONY: all tests clean clean_run clean_all help
