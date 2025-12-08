#ifndef SERVER_SIGN_H
#define SERVER_SIGN_H

#include "../common/crypto_utils.h"
#include "../common/network.h"
#include "../common/params.h"

#include <errno.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/types.h>
#include <string.h>

typedef struct {
  BIGNUM *st_s;
  BIGNUM *ct_c1;
  BIGNUM *ct_c2;
  BIGNUM *c;
  BIGNUM *sid;
} sign_data_t;

extern sign_data_t sign_data;

extern int received;

int init_sign_data();

//回调函数，根据收到的消息类型处理数据
void sign_message_handler(const NetworkMessage *msg);

int commit();

int server_sign();

void free_sign_data();

#endif