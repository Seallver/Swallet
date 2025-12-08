#ifndef SERVER_KEYGEN_H
#define SERVER_KEYGEN_H

#include "../common/crypto_utils.h"
#include "../common/network.h"
#include "../common/params.h"

#include <openssl/bn.h>
#include <openssl/ec.h>

// 密钥对结构体
typedef struct {
  BIGNUM *sk_s;
  EC_POINT *pk;
} key_pair_t;

extern key_pair_t key_pair;

//回调函数
void keygen_message_handler(const NetworkMessage *msg);

int recv_sk_pk();

void free_key_pair();

#endif