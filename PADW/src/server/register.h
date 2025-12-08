#ifndef SERVER_REGISTER_H
#define SERVER_REGISTER_H

#include "../common/crypto_utils.h"
#include "../common/network.h"
#include "../common/params.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <stdio.h>
#include <string.h>

// 注册结构体
typedef struct {
  BIGNUM *tau;
  BIGNUM *sk_PKE;
  BIGNUM *p;
  BIGNUM *g;
} register_pair_t;

extern register_pair_t register_pair;

int generate_register_pair();
void free_register_pair();

#endif