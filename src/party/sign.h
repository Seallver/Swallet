#ifndef PARTY_SIGN_H
#define PARTY_SIGN_H

#include "../common/crypto_utils.h"
#include "../common/network.h"
#include "../common/params.h"
#include "presign.h"
#include "pthread.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/types.h>
#include <string.h>
#include <sys/time.h>

extern int received;

//签名上下文结构体
typedef struct {

  //公开参数
  EC_POINT *a;
  EC_POINT *b;

  BIGNUM *beta_i;          // 随机数 β_i
  EC_POINT *delta_i;       // ▲_i = Γ_i^{β_i}
  EC_POINT *rw_i;          // rw_i = sw_i^{β_i}
  EC_POINT *L_i;           // 从协调者接收的 L_i
  EC_POINT *M_i;           // M_i = g^{ν_i} · b^{rw_i}
  EC_POINT *N_i;           // N_i = (L_i / a^{rw_i})^{ν_i}
  unsigned char key_i[32]; // 会话密钥

  unsigned char H_msg[32];

  BIGNUM *sigma_i; // 签名份额 σ_i

} Party;

extern Party party;

extern int sign_flag;
extern int offline_id;

int init_party();

//回调函数，根据收到的消息类型处理数据
void sign_message_handler(const NetworkMessage *msg);

int step2();

int step4();

int step7();

void free_party();

#endif