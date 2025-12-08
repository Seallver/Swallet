#include "keygen.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <stdio.h>
#include <string.h>

key_pair_t key_pair = {0};

int generate_key_pair() {
  if (!sys_params.group || !sys_params.q) {
    fprintf(stderr, "Invalid parameters\n");
    return 0;
  }

  BN_CTX *ctx = BN_CTX_new();
  key_pair.pk = EC_POINT_new(sys_params.group);
  key_pair.sd = BN_new();
  key_pair.sk_u = BN_new();

  // 随机生成私钥
  BIGNUM *sk = BN_new();
  if (!random_in_Zq(sk)) {
    fprintf(stderr, "Failed to generate sk\n");
    free_key_pair(key_pair);
    return 0;
  }

  // 计算公钥
  if (!EC_POINT_mul(sys_params.group, key_pair.pk, sk, NULL, NULL, ctx)) {
    fprintf(stderr, "Failed to compute public share g^{sk}\n");
    free_key_pair(key_pair);
    return 0;
  }

  // 随机生成sd
  if (!random_BN(key_pair.sd)) {
    fprintf(stderr, "Failed to generate sd\n");
    free_key_pair(key_pair);
  }

  // 随机生成sk_s
  BIGNUM *sk_s = BN_new();
  if (!random_in_Zq(sk_s)) {
    fprintf(stderr, "Failed to generate sk\n");
    free_key_pair(key_pair);
    return 0;
  }

  // 计算sk_u
  if (!BN_mod_sub(key_pair.sk_u, sk, sk_s, sys_params.q, ctx)) {
    fprintf(stderr, "Failed to compute sk_u\n");
    free_key_pair(key_pair);
    return 0;
  }

  // 发送sk_s和pk
  char buffer[192];

  serialize_bn(buffer, sk_s);
  serialize_ec_point(buffer + 64, key_pair.pk);

  int port = sys_params.parties[0].port;
  char *ip = sys_params.parties[0].ip;

  send_message(1, ip, port, DATA_SK_PK, buffer);

  BN_CTX_free(ctx);

  // 擦除sk和sk_s
  BN_free(sk);
  BN_free(sk_s);

  return 1;
}

void free_key_pair() {
  if (key_pair.sk_u) {
    BN_free(key_pair.sk_u);
    key_pair.sk_u = NULL;
  }
  if (key_pair.pk) {
    EC_POINT_free(key_pair.pk);
    key_pair.pk = NULL;
  }
  if (key_pair.sd) {
    BN_free(key_pair.sd);
    key_pair.sd = NULL;
  }
}
