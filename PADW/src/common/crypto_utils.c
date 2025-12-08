#include "crypto_utils.h"
#include "params.h"
#include <arpa/inet.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <string.h>

int H1(const BIGNUM *in_bn, const char *tag, BIGNUM *result) {
  if (!in_bn || !tag || !result || !sys_params.q)
    return 0;

  int ret = 0;
  EVP_MD_CTX *mdctx = NULL;
  const EVP_MD *md = EVP_sha256();
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len = 0;

  // 创建 Digest 上下文
  mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    return 0;

  // 初始化 SHA-256
  if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
    goto cleanup;

  // 输入 BIGNUM → binary
  int bn_len = BN_num_bytes(in_bn);
  unsigned char *bn_buf = OPENSSL_malloc(bn_len);
  if (!bn_buf)
    goto cleanup;

  BN_bn2bin(in_bn, bn_buf);

  if (EVP_DigestUpdate(mdctx, bn_buf, bn_len) != 1) {
    OPENSSL_free(bn_buf);
    goto cleanup;
  }
  OPENSSL_free(bn_buf);

  // 输入 tag string
  if (EVP_DigestUpdate(mdctx, tag, strlen(tag)) != 1)
    goto cleanup;

  // 完成哈希
  if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
    goto cleanup;

  // 将 hash 变成 BIGNUM
  BIGNUM *h = BN_bin2bn(hash, hash_len, NULL);
  if (!h)
    goto cleanup;

  // 映射到 Z_q* = {1 .. q-1}
  BIGNUM *q_minus_1 = BN_dup(sys_params.q);
  if (!q_minus_1) {
    BN_free(h);
    goto cleanup;
  }
  BN_sub_word(q_minus_1, 1);

  BN_CTX *bn_ctx = BN_CTX_new();
  if (!bn_ctx) {
    BN_free(h);
    BN_free(q_minus_1);
    goto cleanup;
  }

  // result = (h mod (q-1)) + 1
  if (BN_mod(result, h, q_minus_1, bn_ctx) != 1) {
    BN_free(h);
    BN_free(q_minus_1);
    BN_CTX_free(bn_ctx);
    goto cleanup;
  }

  BN_add_word(result, 1);

  BN_free(h);
  BN_free(q_minus_1);
  BN_CTX_free(bn_ctx);

  ret = 1; // success

cleanup:
  EVP_MD_CTX_free(mdctx);
  return ret;
}

int H2(const EC_POINT *P, const EC_POINT *R, const char *tag, BIGNUM *result) {
  if (!P || !R || !tag || !result || !sys_params.group || !sys_params.q)
    return 0;

  int ret = 0;
  EVP_MD_CTX *mdctx = NULL;
  const EVP_MD *md = EVP_sha256();
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len = 0;

  BN_CTX *bn_ctx_tmp = NULL;
  unsigned char *bufP = NULL;
  unsigned char *bufR = NULL;

  // --- Step 1: Create Digest context ---
  mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    return 0;

  if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
    goto cleanup;

  // --- Step 2: Serialize EC_POINT P ---
  bn_ctx_tmp = BN_CTX_new();
  if (!bn_ctx_tmp)
    goto cleanup;

  size_t lenP = EC_POINT_point2oct(
      sys_params.group, P, POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx_tmp);
  if (lenP == 0)
    goto cleanup;

  bufP = OPENSSL_malloc(lenP);
  if (!bufP)
    goto cleanup;

  if (!EC_POINT_point2oct(sys_params.group, P, POINT_CONVERSION_COMPRESSED,
                          bufP, lenP, bn_ctx_tmp))
    goto cleanup;

  if (EVP_DigestUpdate(mdctx, bufP, lenP) != 1)
    goto cleanup;

  // --- Step 3: Serialize EC_POINT R ---
  size_t lenR = EC_POINT_point2oct(
      sys_params.group, R, POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx_tmp);
  if (lenR == 0)
    goto cleanup;

  bufR = OPENSSL_malloc(lenR);
  if (!bufR)
    goto cleanup;

  if (!EC_POINT_point2oct(sys_params.group, R, POINT_CONVERSION_COMPRESSED,
                          bufR, lenR, bn_ctx_tmp))
    goto cleanup;

  if (EVP_DigestUpdate(mdctx, bufR, lenR) != 1)
    goto cleanup;

  // --- Step 4: Hash tag string ---
  if (EVP_DigestUpdate(mdctx, tag, strlen(tag)) != 1)
    goto cleanup;

  // --- Step 5: Finalize SHA256 ---
  if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
    goto cleanup;

  // --- Step 6: Convert hash → BIGNUM h ---
  BIGNUM *h = BN_bin2bn(hash, hash_len, NULL);
  if (!h)
    goto cleanup;

  // --- Step 7: Compute result = (h mod (q-1)) + 1 ---
  BIGNUM *q_minus_1 = BN_dup(sys_params.q);
  if (!q_minus_1) {
    BN_free(h);
    goto cleanup;
  }
  BN_sub_word(q_minus_1, 1);

  BN_CTX *bn_ctx2 = BN_CTX_new();
  if (!bn_ctx2) {
    BN_free(h);
    BN_free(q_minus_1);
    goto cleanup;
  }

  if (BN_mod(result, h, q_minus_1, bn_ctx2) != 1) {
    BN_free(h);
    BN_free(q_minus_1);
    BN_CTX_free(bn_ctx2);
    goto cleanup;
  }

  BN_add_word(result, 1);

  BN_free(h);
  BN_free(q_minus_1);
  BN_CTX_free(bn_ctx2);

  ret = 1; // success

cleanup:
  if (bufP)
    OPENSSL_free(bufP);
  if (bufR)
    OPENSSL_free(bufR);
  if (bn_ctx_tmp)
    BN_CTX_free(bn_ctx_tmp);
  EVP_MD_CTX_free(mdctx);
  return ret;
}

int H3(const BIGNUM *a, const BIGNUM *b, const BIGNUM *c, BIGNUM *result) {

  if (!a || !b || !c || !result || !sys_params.q)
    return 0;

  int ret = 0;
  EVP_MD_CTX *mdctx = NULL;
  const EVP_MD *md = EVP_sha256();
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len = 0;

  unsigned char *bufA = NULL;
  unsigned char *bufB = NULL;
  unsigned char *bufC = NULL;

  // --- Step 1: Init Digest ---
  mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    return 0;

  if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
    goto cleanup;

  // --- Step 2: Feed BIGNUM a ---
  int lenA = BN_num_bytes(a);
  bufA = OPENSSL_malloc(lenA);
  if (!bufA)
    goto cleanup;
  BN_bn2bin(a, bufA);

  if (EVP_DigestUpdate(mdctx, bufA, lenA) != 1)
    goto cleanup;

  // --- Step 3: Feed BIGNUM b ---
  int lenB = BN_num_bytes(b);
  bufB = OPENSSL_malloc(lenB);
  if (!bufB)
    goto cleanup;
  BN_bn2bin(b, bufB);

  if (EVP_DigestUpdate(mdctx, bufB, lenB) != 1)
    goto cleanup;

  // --- Step 4: Feed BIGNUM c ---
  int lenC = BN_num_bytes(c);
  bufC = OPENSSL_malloc(lenC);
  if (!bufC)
    goto cleanup;
  BN_bn2bin(c, bufC);

  if (EVP_DigestUpdate(mdctx, bufC, lenC) != 1)
    goto cleanup;

  // --- Step 5: Finalize SHA256 ---
  if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
    goto cleanup;

  // --- Step 6: Convert hash → BIGNUM h ---
  BIGNUM *h = BN_bin2bn(hash, hash_len, NULL);
  if (!h)
    goto cleanup;

  BIGNUM *q_minus_1 = BN_dup(sys_params.q);
  if (!q_minus_1) {
    BN_free(h);
    goto cleanup;
  }
  BN_sub_word(q_minus_1, 1);

  BN_CTX *bn_ctx = BN_CTX_new();
  if (!bn_ctx) {
    BN_free(h);
    BN_free(q_minus_1);
    goto cleanup;
  }

  // result = (h mod (q-1)) + 1
  if (BN_mod(result, h, q_minus_1, bn_ctx) != 1) {
    BN_free(h);
    BN_free(q_minus_1);
    BN_CTX_free(bn_ctx);
    goto cleanup;
  }

  BN_add_word(result, 1);

  BN_free(h);
  BN_free(q_minus_1);
  BN_CTX_free(bn_ctx);

  ret = 1; // success

cleanup:
  if (bufA)
    OPENSSL_free(bufA);
  if (bufB)
    OPENSSL_free(bufB);
  if (bufC)
    OPENSSL_free(bufC);
  EVP_MD_CTX_free(mdctx);
  return ret;
}

int random_BN(BIGNUM *res) {
  if (BN_rand(res, LAMBDA, 0, 0) != 1) {
    return 0;
  }
  return 1;
}

int random_in_Zq(BIGNUM *result) { return BN_rand_range(result, sys_params.q); }

int random_in_Zq_star(BIGNUM *result) {
  // 生成 [1, q-1] 范围内的随机数
  BIGNUM *q_minus_one = BN_new();
  BN_copy(q_minus_one, sys_params.q);
  BN_sub_word(q_minus_one, 1);

  int success = BN_rand_range(result, q_minus_one);
  if (success) {
    BN_add_word(result, 1); // 映射到 [1, q-1]
  }

  BN_free(q_minus_one);
  return success;
}

int random_in_Group(EC_POINT *result) {
  BIGNUM *a = BN_new();
  int success = random_in_Zq_star(a);
  if (success) {
    EC_POINT_mul(sys_params.group, result, a, NULL, NULL, NULL);
  }

  BN_free(a);
  return success;
}

// H4: 把椭圆曲线群元素映射为 Z_q*
int H4(EC_POINT *point, BIGNUM *result) {
  unsigned char hash[HASH_LEN];
  unsigned char *point_bin = NULL;
  size_t point_len;
  BN_CTX *ctx = BN_CTX_new();

  if (!ctx || !point)
    return 0;

  // 获取点的字节表示长度
  point_len = EC_POINT_point2oct(sys_params.group, point,
                                 POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
  if (point_len == 0) {
    BN_CTX_free(ctx);
    return 0;
  }

  // 分配内存并获取点的字节表示
  point_bin = (unsigned char *)OPENSSL_malloc(point_len);
  if (!point_bin) {
    BN_CTX_free(ctx);
    return 0;
  }

  if (EC_POINT_point2oct(sys_params.group, point, POINT_CONVERSION_COMPRESSED,
                         point_bin, point_len, NULL) != point_len) {
    OPENSSL_free(point_bin);
    BN_CTX_free(ctx);
    return 0;
  }

  // 使用 SHA-256 计算哈希
  if (!SHA256(point_bin, point_len, hash)) {
    OPENSSL_free(point_bin);
    BN_CTX_free(ctx);
    return 0;
  }

  OPENSSL_free(point_bin);

  // 将哈希转换为 BIGNUM
  if (!BN_bin2bn(hash, HASH_LEN, result)) {
    BN_CTX_free(ctx);
    return 0;
  }

  // 创建 q-1
  BIGNUM *q_minus_one = BN_dup(sys_params.q);
  if (!q_minus_one || !BN_sub_word(q_minus_one, 1)) {
    BN_CTX_free(ctx);
    if (q_minus_one)
      BN_free(q_minus_one);
    return 0;
  }

  // 取模运算，确保在 [0, q-2] 范围内
  if (!BN_mod(result, result, q_minus_one, ctx)) {
    BN_free(q_minus_one);
    BN_CTX_free(ctx);
    return 0;
  }

  // 加 1 确保在 [1, q-1] 范围内 (Z_q*)
  if (!BN_add_word(result, 1)) {
    BN_free(q_minus_one);
    BN_CTX_free(ctx);
    return 0;
  }

  BN_free(q_minus_one);
  BN_CTX_free(ctx);
  return 1;
}

int get_point_x_coordinate(EC_POINT *point, BIGNUM *x) {
  BN_CTX *ctx = BN_CTX_new();
  if (!ctx)
    return 0;

  int ret =
      EC_POINT_get_affine_coordinates(sys_params.group, point, x, NULL, ctx);
  BN_CTX_free(ctx);
  return ret;
}

int ElGamal_keygen(BIGNUM *p, BIGNUM *g, BIGNUM *x, BIGNUM *y) {
  int bits = 256;
  BN_CTX *ctx = BN_CTX_new();
  if (!ctx)
    return 0;

  // 1) 生成安全素数 p（也可以用普通素数）
  if (BN_generate_prime_ex(p, bits, 1, NULL, NULL, NULL) != 1)
    return 0;

  // 2) 选择 g （简单取 2，也可取更复杂生成元）
  BN_set_word(g, 2);

  // 3) 生成私钥 x ∈ [1, p-2]
  BIGNUM *p_minus_2 = BN_dup(p);
  BN_sub_word(p_minus_2, 2);
  BN_rand_range(x, p_minus_2);

  // 4) 计算公钥 y = g^x mod p
  BN_mod_exp(y, g, x, p, ctx);

  BN_free(p_minus_2);
  BN_CTX_free(ctx);
  return 1;
}

int ElGamal_enc(const BIGNUM *p, const BIGNUM *g, const BIGNUM *y,
                const BIGNUM *m, BIGNUM *c1, BIGNUM *c2) {
  BN_CTX *ctx = BN_CTX_new();
  if (!ctx)
    return 0;

  BIGNUM *k = BN_new();
  BIGNUM *yk = BN_new();

  // k ∈ [1, p-2]
  BIGNUM *p_minus_2 = BN_dup(p);
  BN_sub_word(p_minus_2, 2);
  BN_rand_range(k, p_minus_2);

  // c1 = g^k mod p
  BN_mod_exp(c1, g, k, p, ctx);

  // yk = y^k mod p
  BN_mod_exp(yk, y, k, p, ctx);

  // c2 = m * y^k mod p
  BN_mod_mul(c2, m, yk, p, ctx);

  BN_free(p_minus_2);
  BN_free(k);
  BN_free(yk);
  BN_CTX_free(ctx);
  return 1;
}

int ElGamal_dec(const BIGNUM *p, const BIGNUM *x, const BIGNUM *c1,
                const BIGNUM *c2, BIGNUM *m) {
  BN_CTX *ctx = BN_CTX_new();
  if (!ctx)
    return 0;

  BIGNUM *s = BN_new();
  BIGNUM *s_inv = BN_new();

  // s = c1^x mod p
  BN_mod_exp(s, c1, x, p, ctx);

  // s_inv = s^{-1} mod p
  BN_mod_inverse(s_inv, s, p, ctx);

  // m = c2 * s_inv mod p
  BN_mod_mul(m, c2, s_inv, p, ctx);

  BN_free(s);
  BN_free(s_inv);
  BN_CTX_free(ctx);
  return 1;
}

BIGNUM *generate_sid_bn_from_R(const EC_POINT *R) {
  if (!R || !sys_params.group)
    return NULL;

  unsigned char hash[32];
  EVP_MD_CTX *mdctx = NULL;
  BIGNUM *sid_bn = NULL;

  //  序列化 R
  size_t r_len = EC_POINT_point2oct(sys_params.group, R,
                                    POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
  if (r_len == 0)
    return NULL;

  uint8_t *r_buf = OPENSSL_malloc(r_len);
  if (!r_buf)
    return NULL;

  EC_POINT_point2oct(sys_params.group, R, POINT_CONVERSION_COMPRESSED, r_buf,
                     r_len, NULL);

  //  哈希：SHA256(R_bytes)
  mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    goto cleanup;

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
    goto cleanup;

  EVP_DigestUpdate(mdctx, r_buf, r_len);

  unsigned int out_len = 0;
  if (EVP_DigestFinal_ex(mdctx, hash, &out_len) != 1)
    goto cleanup;

  // hash → BIGNUM
  sid_bn = BN_bin2bn(hash, out_len, NULL);

cleanup:
  EVP_MD_CTX_free(mdctx);
  OPENSSL_free(r_buf);

  return sid_bn;
}
