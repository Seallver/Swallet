#ifndef USER_KEYGEN_H
#define USER_KEYGEN_H

#include "../common/crypto_utils.h"
#include "../common/network.h"
#include "../common/params.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

// 密钥对结构体
typedef struct {
  BIGNUM *sk_u;
  EC_POINT *pk;
  BIGNUM *sd;
} key_pair_t;

extern key_pair_t key_pair;

int generate_key_pair();
void free_key_pair();

#endif