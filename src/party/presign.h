#ifndef PARTY_PRESIGN_H
#define PARTY_PRESIGN_H

#include "../common/crypto_utils.h"
#include "../common/network.h"
#include "../common/params.h"
#include "pthread.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/types.h>
#include <sys/time.h>

//预签名结构体
typedef struct {
  EC_POINT *Gamma; // Γ = g^{a}
  EC_POINT *sw;    // sw = Γ^h

  BIGNUM *k;       // 临时私钥
  BIGNUM *phi;     // 随机数 phi
  BIGNUM *x;       // 私钥份额
  EC_POINT *R;     // R = g^{k}
  EC_POINT *sum_R; // 多方R聚合
  BIGNUM *r;

  BIGNUM *u; // 预签名材料 u
  BIGNUM *v; // 预签名材料 v

  BIGNUM *pre_u;   // 上一个参与方的u
  BIGNUM *pre_phi; // 上一个参与方的phi
  BIGNUM *pre_v;   // 上一个参与方的v
} PresignData;

typedef struct {
  EC_POINT *Gamma;
  EC_POINT *sw;
  BIGNUM *pre_k;
  BIGNUM *pre_phi;
  BIGNUM *pre_x;
  BIGNUM *pre_u;
  BIGNUM *pre_v;
  int received;
  int R_received;
} RecvData;

extern PresignData presign_data;

extern RecvData recv_data;

int init_presign();

//回调函数，根据收到的消息类型处理数据
void presign_message_handler(const NetworkMessage *msg);

int send_k_phi_x();

int compute_u_v();

int exchange_u_v();

int send_u_v();

int public_R();

void free_presigndata();

void free_recvdata();

#endif