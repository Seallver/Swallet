#ifndef PARTY_KEYGEN_H
#define PARTY_KEYGEN_H

#include "../common/crypto_utils.h"
#include "../common/params.h"
#include "presign.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

// 密钥对结构体
typedef struct {
  BIGNUM *secret_share;   // 秘密份额 x_i
  EC_POINT *public_share; // 公开份额 y_i = g^{x_i}
  EC_POINT *vk;           // 聚合总公钥vk
} key_pair_t;

extern key_pair_t key_pair;

extern int vk_received_count;

//回调函数，这里只需要聚合公钥
void keygen_message_handler(const NetworkMessage *msg);

int generate_key_pair();
void free_key_pair();

int public_VK();

#endif