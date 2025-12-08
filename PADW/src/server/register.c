#include "register.h"
#include <openssl/bn.h>
#include <openssl/types.h>

register_pair_t register_pair = {0};

int generate_register_pair() {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *phi = BN_new();
  register_pair.tau = BN_new();
  register_pair.g = BN_new();
  register_pair.p = BN_new();
  register_pair.sk_PKE = BN_new();

  if (!random_in_Zq(phi)) {
    fprintf(stderr, "Failed to generate register pair\n");
    return 0;
  }

  if (!H1(phi, PASSWORD, register_pair.tau)) {
    fprintf(stderr, "Failed to generate register pair\n");
    return 0;
  }

  BIGNUM *pk_PKE = BN_new();
  if (!ElGamal_keygen(register_pair.p, register_pair.g, register_pair.sk_PKE,
                      pk_PKE)) {
    fprintf(stderr, "Failed to generate elgamal pair\n");
    return 0;
  }

  //发送p、g、pk、phi
  char buffer[256];

  serialize_bn(buffer, register_pair.p);
  serialize_bn(buffer + 64, register_pair.g);
  serialize_bn(buffer + 128, pk_PKE);
  serialize_bn(buffer + 192, phi);

  int port = sys_params.parties[1].port;
  char *ip = sys_params.parties[1].ip;

  send_message(1, ip, port, DATA_ELGAMAL_PARAMS, buffer);

  BN_CTX_free(ctx);
  BN_free(phi);
  BN_free(pk_PKE);
  return 1;
}

void free_register_pair() {
  if (register_pair.g) {
    BN_free(register_pair.g);
  }
  if (register_pair.p) {
    BN_free(register_pair.p);
  }
  if (register_pair.sk_PKE) {
    BN_free(register_pair.sk_PKE);
  }
}