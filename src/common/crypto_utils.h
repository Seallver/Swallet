#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include "params.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

// H1: {0,1}* -> Z_q*
int H1(const unsigned char *input, size_t input_len, BIGNUM *result);

// H2: {0,1}* -> {0,1}^256
int H2(const unsigned char *input, size_t input_len, unsigned char *output);

// 在 Z_q 中生成随机数
int random_in_Zq(BIGNUM *result);

// 在 Z_q* 中生成随机数
int random_in_Zq_star(BIGNUM *result);

// 随机生成群元素
int random_in_Group(EC_POINT *result);

// H3: 把椭圆曲线群元素映射为 Z_q*
int H3(EC_POINT *point, BIGNUM *result);

// 获取点元素的横坐标
int get_point_x_coordinate(EC_POINT *point, BIGNUM *x);

// 对称加密解密
int Enc(unsigned char key[32], unsigned char *msg, int msg_len,
        unsigned char *res);
int Dec(unsigned char key[32], unsigned char *ct, unsigned char *res);

#endif