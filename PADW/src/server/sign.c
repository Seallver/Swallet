#include "sign.h"
#include "keygen.h"
#include "register.h"
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdio.h>

sign_data_t sign_data = {0};

int received = 0;

int init_sign_data() {

  sign_data.st_s = BN_new();
  sign_data.ct_c1 = BN_new();
  sign_data.ct_c2 = BN_new();
  sign_data.c = BN_new();
  sign_data.sid = BN_new();

  if (!sign_data.st_s || !sign_data.ct_c1 || !sign_data.ct_c2 || !sign_data.c ||
      !sign_data.sid) {
    fprintf(stderr, "failed to init sign data\n");
    return 0;
  }
  return 1;
}

void sign_message_handler(const NetworkMessage *msg) {
  if (!msg)
    return;

  int type = msg->type;

  switch (type) {
  case DATA_C_CT: {
    sign_data.ct_c1 = deserialize_bn(msg->data);
    sign_data.ct_c2 = deserialize_bn(msg->data + 64);
    sign_data.c = deserialize_bn(msg->data + 128);
    received = 1;
    break;
  }
  default: {
    printf("message type error\n");
  }
  }
};

int commit() {

  BIGNUM *r = BN_new();
  if (!random_in_Zq_star(r)) {
    fprintf(stderr, "failed to gen r\n");
    return 0;
  }

  sign_data.st_s = BN_dup(r);

  EC_POINT *R = EC_POINT_new(sys_params.group);
  if (!EC_POINT_mul(sys_params.group, R, r, NULL, NULL, NULL)) {
    fprintf(stderr, "failed to compute R\n");
    return 0;
  }

  sign_data.sid = generate_sid_bn_from_R(R);

  char buffer[128];
  serialize_ec_point(buffer, R);
  int port = sys_params.parties[1].port;
  char *ip = sys_params.parties[1].ip;

  send_message(0, ip, port, DATA_R, buffer);

  EC_POINT_free(R);
  BN_free(r);

  return 1;
}

int server_sign() {
  BN_CTX *ctx = BN_CTX_new();

  //计算h'
  BIGNUM *hash_prime = BN_new();
  if (!ElGamal_dec(register_pair.p, register_pair.sk_PKE, sign_data.ct_c1,
                   sign_data.ct_c2, hash_prime)) {
    fprintf(stderr, "Dec failed\n");
    return 0;
  }

  //计算h
  BIGNUM *hash = BN_new();
  if (!H3(sign_data.sid, sign_data.c, register_pair.tau, hash)) {
    fprintf(stderr, "Compute h' failed\n");
    return 0;
  }

  //检验是否相等
  if (BN_cmp(hash_prime, hash) != 0) {
    fprintf(stderr, "check failed\n");
    return 0;
  }

  //签名，计算s
  BIGNUM *s = BN_new();
  if (!BN_mod_mul(s, sign_data.c, key_pair.sk_s, sys_params.q, ctx)) {
    fprintf(stderr, "Compute c*sk failed\n");
    return 0;
  }

  if (!BN_mod_add(s, s, sign_data.st_s, sys_params.q, ctx)) {
    fprintf(stderr, "Compute s failed\n");
    return 0;
  }

  //发送s
  char buffer[64];

  serialize_bn(buffer, s);

  int port = sys_params.parties[1].port;
  char *ip = sys_params.parties[1].ip;

  send_message(0, ip, port, DATA_S, buffer);

  BN_free(hash_prime);
  BN_free(hash);
  BN_CTX_free(ctx);
  BN_free(s);
  return 1;
}

void free_sign_data() {
  if (sign_data.st_s)
    BN_free(sign_data.st_s);
  if (sign_data.ct_c1)
    BN_free(sign_data.ct_c1);
  if (sign_data.ct_c2)
    BN_free(sign_data.ct_c2);
  if (sign_data.c)
    BN_free(sign_data.c);
  if (sign_data.sid)
    BN_free(sign_data.sid);
}
