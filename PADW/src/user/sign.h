#ifndef USER_SIGN_H
#define USER_SIGN_H

#include "../common/crypto_utils.h"
#include "../common/network.h"
#include "../common/params.h"

#include "keyDerivation.h"
#include "keygen.h"
#include "register.h"

#include "pthread.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/types.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

//签名上下文结构体
typedef struct {
  BIGNUM *alpha;
  BIGNUM *beta;
  EC_POINT *R;
  BIGNUM *ct_c1;
  BIGNUM *ct_c2;
  BIGNUM *c;
  BIGNUM *c_prime;
  BIGNUM *s;
  EC_POINT *R_prime;
  BIGNUM *s_prime;
} sign_data_t;

extern sign_data_t sign_data;

extern int received;

int init_sign_data();

//回调函数，根据收到的消息类型处理数据
void sign_message_handler(const NetworkMessage *msg);

int gen_challenge();

int user_sign();

int verify();

void free_sign_data();

#endif