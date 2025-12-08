#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include "params.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

// H1: (BN,char) -> Z_q*
int H1(const BIGNUM *in_bn, const char *tag, BIGNUM *result);

// H2: (EC_POINT,EC_POINT,char) -> Z_q*
int H2(const EC_POINT *P, const EC_POINT *R, const char *tag, BIGNUM *result);

// H3: (BN,BN,BN)-> Z_q*
int H3(const BIGNUM *a, const BIGNUM *b, const BIGNUM *c, BIGNUM *result);

//随机生成一个指定比特的BN
int random_BN(BIGNUM *res);

// 在 Z_q 中生成随机数
int random_in_Zq(BIGNUM *result);

// 在 Z_q* 中生成随机数
int random_in_Zq_star(BIGNUM *result);

// 随机生成群元素
int random_in_Group(EC_POINT *result);

// H4: 把椭圆曲线群元素映射为 Z_q*
int H4(EC_POINT *point, BIGNUM *result);

// 获取点元素的横坐标
int get_point_x_coordinate(EC_POINT *point, BIGNUM *x);

int ElGamal_keygen(BIGNUM *p, BIGNUM *g, BIGNUM *x, BIGNUM *y);
int ElGamal_enc(const BIGNUM *p, const BIGNUM *g, const BIGNUM *y,
                const BIGNUM *m, BIGNUM *c1, BIGNUM *c2);
int ElGamal_dec(const BIGNUM *p, const BIGNUM *x, const BIGNUM *c1,
                const BIGNUM *c2, BIGNUM *m);

// 计算sid
BIGNUM *generate_sid_bn_from_R(const EC_POINT *R);

#endif