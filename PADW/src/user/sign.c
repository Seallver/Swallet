#include "sign.h"
#include "keygen.h"
#include "register.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/types.h>

sign_data_t sign_data = {0};
int received = 0;

int init_sign_data() {

  sign_data.alpha = BN_new();
  sign_data.beta = BN_new();
  sign_data.ct_c1 = BN_new();
  sign_data.ct_c2 = BN_new();
  sign_data.c = BN_new();
  sign_data.c_prime = BN_new();
  sign_data.s = BN_new();
  sign_data.s_prime = BN_new();
  sign_data.R = EC_POINT_new(sys_params.group);
  sign_data.R_prime = EC_POINT_new(sys_params.group);

  if (!sign_data.alpha || !sign_data.beta || !sign_data.ct_c1 ||
      !sign_data.ct_c2 || !sign_data.c || !sign_data.c_prime || !sign_data.R ||
      !sign_data.s || !sign_data.R_prime || !sign_data.s_prime) {
    printf("failed to init sign data\n");
    free_sign_data();
    return 0;
  }

  return 1;
}

void sign_message_handler(const NetworkMessage *msg) {
  if (!msg)
    return;

  int type = msg->type;

  switch (type) {
  case DATA_R: {
    sign_data.R = deserialize_ec_point(msg->data);
    received = 1;
    break;
  }
  case DATA_S: {
    sign_data.s = deserialize_bn(msg->data);
    received = 1;
    break;
  }
  default: {
    printf("message type error\n");
  }
  }
};

int gen_challenge() {
  //随机生成α、β
  BIGNUM *alpha = BN_new();
  BIGNUM *beta = BN_new();
  if (!random_in_Zq_star(alpha) || !random_in_Zq_star(beta)) {
    fprintf(stderr, "Gen alpha and beta failed\n");
    return 0;
  }

  BN_CTX *ctx = BN_CTX_new();

  //计算R'
  EC_POINT *R_prime = EC_POINT_new(sys_params.group);
  if (!EC_POINT_mul(sys_params.group, R_prime, alpha, key_pair.pk, beta, ctx)) {
    fprintf(stderr, "Compute R' failed\n");
    return 0;
  }

  if (!EC_POINT_add(sys_params.group, R_prime, R_prime, sign_data.R, ctx)) {
    fprintf(stderr, "Compute R' failed\n");
    return 0;
  }

  //计算挑战哈希
  BIGNUM *c_prime = BN_new();
  if (!H2(R_prime, key_pair.pk, MESSAGE, c_prime)) {
    fprintf(stderr, "Compute c' failed\n");
    return 0;
  }

  sign_data.c_prime = BN_dup(c_prime);
  sign_data.alpha = BN_dup(alpha);
  sign_data.beta = BN_dup(beta);

  if (!BN_mod_add(sign_data.c, c_prime, beta, sys_params.q, ctx)) {
    fprintf(stderr, "Compute c failed\n");
    return 0;
  }

  //计算sid
  BIGNUM *sid = generate_sid_bn_from_R(sign_data.R);

  //计算消息哈希
  BIGNUM *temp = BN_new();
  if (!H1(register_pair.phi, PASSWORD, temp)) {
    fprintf(stderr, "Compute H(phi,pw) failed\n");
    return 0;
  }
  if (!H3(sid, sign_data.c, temp, temp)) {
    fprintf(stderr, "Compute H(sid,c,H(phi,pw)) failed\n");
    return 0;
  }

  //加密
  if (!ElGamal_enc(register_pair.p, register_pair.g, register_pair.pk_PKE, temp,
                   sign_data.ct_c1, sign_data.ct_c2)) {
    fprintf(stderr, "Enc H(sid,c,H(phi,pw)) failed\n");
    return 0;
  }

  char buffer[192];
  serialize_bn(buffer, sign_data.ct_c1);
  serialize_bn(buffer + 64, sign_data.ct_c2);
  serialize_bn(buffer + 128, sign_data.c);

  int port = sys_params.parties[0].port;
  char *ip = sys_params.parties[0].ip;

  send_message(1, ip, port, DATA_C_CT, buffer);

  EC_POINT_free(R_prime);
  BN_CTX_free(ctx);
  BN_free(alpha);
  BN_free(beta);
  BN_free(c_prime);
  BN_free(sid);
  BN_free(temp);
  return 1;
}

int user_sign() {
  // 验证 s 正确性：检查 g^s = R * (pk * g^{-sku})^c
  EC_POINT *left = EC_POINT_new(sys_params.group);
  EC_POINT *right = EC_POINT_new(sys_params.group);
  EC_POINT *temp = EC_POINT_new(sys_params.group);
  BIGNUM *neg_sku = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  if (!left || !right || !temp || !neg_sku || !ctx) {
    fprintf(stderr, "Memory allocation failed\n");
    return 0;
  }

  // 1. left = g^s
  if (!EC_POINT_mul(sys_params.group, left, sign_data.s, NULL, NULL, ctx)) {
    fprintf(stderr, "Compute g^s failed\n");
    return 0;
  }

  // 2. 计算 neg_sku = -sku mod q
  if (!BN_mod_sub(neg_sku, sys_params.q, key_pair.sk_u, sys_params.q, ctx)) {
    fprintf(stderr, "Compute -sku failed\n");
    return 0;
  }

  // 3. 计算 temp = pk * g^{-sku}
  if (!EC_POINT_mul(sys_params.group, temp, NULL, sys_params.g, neg_sku, ctx)) {
    fprintf(stderr, "Compute g^{-sku} failed\n");
    return 0;
  }
  if (!EC_POINT_add(sys_params.group, temp, key_pair.pk, temp, ctx)) {
    fprintf(stderr, "Compute pk * g^{-sku} failed\n");
    return 0;
  }

  // 4. 计算 temp = (pk * g^{-sku})^c
  if (!EC_POINT_mul(sys_params.group, temp, NULL, temp, sign_data.c, ctx)) {
    fprintf(stderr, "Compute (pk * g^{-sku})^c failed\n");
    return 0;
  }

  // 5. 计算 right = R * (pk * g^{-sku})^c
  if (!EC_POINT_add(sys_params.group, right, sign_data.R, temp, ctx)) {
    fprintf(stderr, "Compute right side failed\n");
    return 0;
  }

  // 6. 比较 left 和 right
  if (EC_POINT_cmp(sys_params.group, left, right, ctx) != 0) {
    fprintf(stderr, "Signature verification failed\n");
    fprintf(stderr,
            "Left (g^s) does not equal Right (R * (pk * g^{-sku})^c)\n");
    return 0;
  }

  //计算 R'和s'
  if (!EC_POINT_mul(sys_params.group, sign_data.R_prime, sign_data.alpha,
                    key_pair.pk, sign_data.beta, ctx)) {
    fprintf(stderr, "Failed to compute R'\n");
    return 0;
  }

  if (!EC_POINT_add(sys_params.group, sign_data.R_prime, sign_data.R_prime,
                    sign_data.R, ctx)) {
    fprintf(stderr, "Failed to compute R'\n");
    return 0;
  }

  if (!BN_mod_add(sign_data.s_prime, sign_data.s, sign_data.alpha, sys_params.q,
                  ctx)) {
    fprintf(stderr, "Failed to compute s'\n");
    return 0;
  }

  BIGNUM *c_sku = BN_new();
  if (!BN_mod_mul(c_sku, sign_data.c, key_pair.sk_u, sys_params.q, ctx)) {
    fprintf(stderr, "Failed to compute s'\n");
    return 0;
  }

  if (!BN_mod_add(sign_data.s_prime, sign_data.s_prime, c_sku, sys_params.q,
                  ctx)) {
    fprintf(stderr, "Failed to compute s'\n");
    return 0;
  }

  //检查g^s' = R'pk^c'
  if (!EC_POINT_mul(sys_params.group, left, sign_data.s_prime, NULL, NULL,
                    ctx)) {
    fprintf(stderr, "Failed to compute left\n");
    return 0;
  }

  if (!EC_POINT_mul(sys_params.group, temp, NULL, key_pair.pk,
                    sign_data.c_prime, ctx)) {
    fprintf(stderr, "Failed to compute right\n");
    return 0;
  }

  if (!EC_POINT_add(sys_params.group, right, sign_data.R_prime, temp, ctx)) {
    fprintf(stderr, "Failed to compute right\n");
    return 0;
  }

  if (EC_POINT_cmp(sys_params.group, left, right, ctx) != 0) {
    fprintf(stderr, "Failed to check\n");
    return 0;
  }

  EC_POINT_free(left);
  EC_POINT_free(right);
  EC_POINT_free(temp);
  BN_free(neg_sku);
  BN_CTX_free(ctx);
  return 1;
}

int verify() {

  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *c = BN_new();
  if (!H2(sign_data.R_prime, key_pair.pk, MESSAGE, c)) {
    fprintf(stderr, "Compute c failed\n");
    return 0;
  }

  EC_POINT *left = EC_POINT_new(sys_params.group);
  EC_POINT *right = EC_POINT_new(sys_params.group);

  if (!EC_POINT_mul(sys_params.group, left, sign_data.s_prime, NULL, NULL,
                    ctx)) {
    fprintf(stderr, "Compute left failed\n");
    return 0;
  }

  if (!EC_POINT_mul(sys_params.group, right, NULL, key_pair.pk, c, ctx)) {
    fprintf(stderr, "Compute right failed\n");
    return 0;
  }

  if (!EC_POINT_add(sys_params.group, right, right, sign_data.R_prime, ctx)) {
    fprintf(stderr, "Compute right failed\n");
    return 0;
  }

  if (EC_POINT_cmp(sys_params.group, left, right, ctx) != 0) {
    printf("Signature verification FAILED\n");
    return 0;
  }

  BN_free(c);
  EC_POINT_free(left);
  EC_POINT_free(right);
  BN_CTX_free(ctx);
  return 1;
}

void free_sign_data() {
  if (sign_data.alpha)
    BN_free(sign_data.alpha);
  if (sign_data.beta)
    BN_free(sign_data.beta);
  if (sign_data.ct_c1)
    BN_free(sign_data.ct_c1);
  if (sign_data.ct_c2)
    BN_free(sign_data.ct_c2);
  if (sign_data.c)
    BN_free(sign_data.c);
  if (sign_data.c_prime)
    BN_free(sign_data.c_prime);
  if (sign_data.R)
    EC_POINT_free(sign_data.R);
  if (sign_data.s)
    BN_free(sign_data.s);
  if (sign_data.R_prime)
    EC_POINT_free(sign_data.R_prime);
  if (sign_data.s_prime)
    BN_free(sign_data.s_prime);
}
