#ifndef USER_KEYDERIVATION_H
#define USER_KEYDERIVATION_H

#include "keygen.h"

// 派生后的结构体
typedef struct {
  BIGNUM *sk_u_ID;
  EC_POINT *pk_ID;
} derived_key_pair_t;

extern derived_key_pair_t derived_key_pair;

int RandSK();
int RandPK();

#endif