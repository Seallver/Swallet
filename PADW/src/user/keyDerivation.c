#include "keyDerivation.h"
#include "keygen.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/types.h>

derived_key_pair_t derived_key_pair = {0};

int RandSK() {
  BIGNUM *rho = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  if (!H1(key_pair.sd, sys_params.derivation_ID, rho)) {
    fprintf(stderr, "Failed to generate rho\n");
    return 0;
  }

  derived_key_pair.sk_u_ID = BN_new();

  if (!BN_mod_add(derived_key_pair.sk_u_ID, key_pair.sk_u, rho, sys_params.q,
                  ctx)) {
    fprintf(stderr, "Failed to generate sk_u_ID\n");
    return 0;
  }

  key_pair.sk_u = BN_dup(derived_key_pair.sk_u_ID);

  BN_free(rho);
  BN_CTX_free(ctx);

  return 1;
}

int RandPK() {
  BIGNUM *rho = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  if (!H1(key_pair.sd, sys_params.derivation_ID, rho)) {
    fprintf(stderr, "Failed to generate rho\n");
    return 0;
  }

  derived_key_pair.pk_ID = EC_POINT_new(sys_params.group);

  BIGNUM *one = BN_new();
  BN_one(one);

  if (!EC_POINT_mul(sys_params.group, derived_key_pair.pk_ID, rho, key_pair.pk,
                    one, ctx)) {
    fprintf(stderr, "Failed to generate pk_ID\n");
    return 0;
  }

  key_pair.pk = EC_POINT_dup(derived_key_pair.pk_ID, sys_params.group);

  BN_free(rho);
  BN_free(one);
  BN_CTX_free(ctx);

  return 1;
}