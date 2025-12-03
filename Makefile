CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I$(SRC_DIR)/common
LIBS = -lssl -lcrypto

SRC_DIR = src
COMMON_DIR = $(SRC_DIR)/common
COORDINATOR_DIR = $(SRC_DIR)/coordinator
PARTY_DIR = $(SRC_DIR)/party

COMMON_SRCS = $(wildcard $(COMMON_DIR)/*.c)
COORDINATOR_SRCS = $(COORDINATOR_DIR)/main.c $(COORDINATOR_DIR)/keygen.c $(COORDINATOR_DIR)/presign.c  $(COORDINATOR_DIR)/sign.c  
PARTY_SRCS = $(PARTY_DIR)/main.c $(PARTY_DIR)/keygen.c $(PARTY_DIR)/presign.c $(PARTY_DIR)/sign.c 

COORDINATOR_OBJS = $(COORDINATOR_SRCS:.c=.o) $(COMMON_SRCS:.c=.o)
PARTY_OBJS = $(PARTY_SRCS:.c=.o) $(COMMON_SRCS:.c=.o)

# 所有对象文件
ALL_OBJS = $(COORDINATOR_OBJS) $(PARTY_OBJS)

.PHONY: all clean clean-objs

all: coordinator party
	@echo "Compilation completed, cleaning object files..."
	@$(MAKE) clean-objs

coordinator: $(COORDINATOR_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

party: $(PARTY_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean-objs:
	rm -f $(ALL_OBJS)

clean:
	rm -f coordinator party $(ALL_OBJS)