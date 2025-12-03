#include "crypto_utils.h"
#include "params.h"
#include <arpa/inet.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <string.h>

int H1(const unsigned char *input, size_t input_len, BIGNUM *result) {
  unsigned char hash[HASH_LEN];
  BN_CTX *ctx = BN_CTX_new();

  if (!ctx)
    return 0;

  // 使用 SHA-256 计算哈希
  if (!SHA256(input, input_len, hash)) {
    BN_CTX_free(ctx);
    return 0;
  }

  // 将哈希直接转换为 BIGNUM
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

  // 取模运算
  if (!BN_mod(result, result, q_minus_one, ctx)) {
    BN_free(q_minus_one);
    BN_CTX_free(ctx);
    return 0;
  }

  // 加 1 确保在 [1, q-1] 范围内
  if (!BN_add_word(result, 1)) {
    BN_free(q_minus_one);
    BN_CTX_free(ctx);
    return 0;
  }

  BN_free(q_minus_one);
  BN_CTX_free(ctx);
  return 1;
}

int H2(const unsigned char *input, size_t input_len, unsigned char *output) {
  return SHA256(input, input_len, output) != NULL;
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

// H3: 把椭圆曲线群元素映射为 Z_q*
int H3(EC_POINT *point, BIGNUM *result) {
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

// AES 加密
int Enc(unsigned char key[32], unsigned char *msg, int msg_len,
        unsigned char *res) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  unsigned char iv[16];

  // 生成随机 IV
  if (RAND_bytes(iv, sizeof(iv)) != 1) {
    return -1;
  }

  // 创建并初始化上下文
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    return -1;
  }

  // 初始化加密操作
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  // 将 IV 复制到结果开头
  memcpy(res, iv, sizeof(iv));

  // 执行加密（注意：这里传入msg_len，而不是strlen）
  if (EVP_EncryptUpdate(ctx, res + 16, &len, msg, msg_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len = len;

  // 完成加密（添加PKCS#7填充）
  if (EVP_EncryptFinal_ex(ctx, res + 16 + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  // 返回总长度 (IV + 密文)
  return 16 + ciphertext_len;
}

// AES-256 解密函数
int Dec(unsigned char key[32], unsigned char *packet, unsigned char *res) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  // 提取密文总长度 L
  uint32_t L;
  memcpy(&L, packet, 4);
  L = ntohl(L);

  if (L < 16) {
    return -1;
  }

  // 定位 IV 和密文部分
  unsigned char *iv = packet + 4;
  unsigned char *ct = packet + 4 + 16;
  int ct_len = L - 16;

  // 创建上下文
  if (!(ctx = EVP_CIPHER_CTX_new()))
    return -1;

  // 初始化
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  // 解密
  if (EVP_DecryptUpdate(ctx, res, &len, ct, ct_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len = len;

  // 结束
  if (EVP_DecryptFinal_ex(ctx, res + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len += len;

  // 字符串结束符
  res[plaintext_len] = '\0';

  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}
