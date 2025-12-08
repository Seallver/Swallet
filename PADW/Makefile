CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I$(SRC_DIR)/common
LIBS = -lssl -lcrypto

SRC_DIR = src
COMMON_DIR = $(SRC_DIR)/common
SERVER_DIR = $(SRC_DIR)/server
USER_DIR = $(SRC_DIR)/user

COMMON_SRCS = $(wildcard $(COMMON_DIR)/*.c)
SERVER_SRCS = $(SERVER_DIR)/main.c $(SERVER_DIR)/keygen.c $(SERVER_DIR)/register.c $(SERVER_DIR)/sign.c
USER_SRCS = $(USER_DIR)/main.c $(USER_DIR)/keygen.c $(USER_DIR)/register.c $(USER_DIR)/keyDerivation.c $(USER_DIR)/sign.c

SERVER_OBJS = $(SERVER_SRCS:.c=.o) $(COMMON_SRCS:.c=.o)
USER_OBJS = $(USER_SRCS:.c=.o) $(COMMON_SRCS:.c=.o)

# 所有对象文件
ALL_OBJS = $(SERVER_OBJS) $(USER_OBJS)

.PHONY: all clean clean-objs

all: server user
	@echo "Compilation completed, cleaning object files..."
	@$(MAKE) clean-objs

server: $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

user: $(USER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean-objs:
	rm -f $(ALL_OBJS)

clean:
	rm -f server user $(ALL_OBJS)