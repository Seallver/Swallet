#ifndef COOR_SIGN_H
#define COOR_SIGN_H

#include "../common/crypto_utils.h"
#include "../common/network.h"
#include "../common/params.h"
#include "presign.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#include <string.h>

extern int received;

typedef struct {
  //公开参数
  EC_POINT *a;
  EC_POINT *b;

  EC_POINT **delta_i;    // 从参与方接收的 Delta_i
  EC_POINT **rw_i_prime; // rw_i' = Delta_i^{h'}
  BIGNUM **mu_i;         // μ_i
  EC_POINT **L_i;        // L_i = g^{μ_i} · a^{rw_i'}
  EC_POINT **M_i;        // 从参与方接收的 M_i
  EC_POINT **N_i_prime;  // N_i' = (M_i / b^{rw_i'})^{μ_i}
  unsigned char *key_i_prime[NUM_PARTIES + 1]; // 会话密钥

  //签名分片
  BIGNUM **w_i;
  BIGNUM **u_i;

  BIGNUM *s;
  BIGNUM *r;

} Coordinator;

extern Coordinator coord;

extern int offline_id;

extern int online_count;

//初始化结构体
int init_coordinator();

//回调函数，根据收到的消息类型处理数据
void sign_message_handler(const NetworkMessage *msg);

int step1();

int broadcast_offline();

int step3();

int step5();

int step6();

int step8();

int verify(const BIGNUM *r, const BIGNUM *s, EC_POINT *vk);

void free_coordinator();

#endif