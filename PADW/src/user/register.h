#ifndef USER_REGISTER_H
#define USER_REGISTER_H

#include "../common/crypto_utils.h"
#include "../common/network.h"
#include "../common/params.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

// 密钥对结构体
typedef struct {
  BIGNUM *phi;
  BIGNUM *pk_PKE;
  BIGNUM *p;
  BIGNUM *g;
} register_pair_t;

extern register_pair_t register_pair;

//回调函数
void register_message_handler(const NetworkMessage *msg);

int recv_elgamal_params();

void free_register_pair();

#endif