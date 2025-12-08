#include "register.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

register_pair_t register_pair = {0};

void register_message_handler(const NetworkMessage *msg) {
  if (!msg)
    return;

  int type = msg->type;

  switch (type) {
  case DATA_ELGAMAL_PARAMS: {
    register_pair.p = deserialize_bn(msg->data);
    register_pair.g = deserialize_bn(msg->data + 64);
    register_pair.pk_PKE = deserialize_bn(msg->data + 128);
    register_pair.phi = deserialize_bn(msg->data + 192);

    listen_thread_exit = 1;
    break;
  }
  default: {
    printf("message type error\n");
  }
  }
}

int recv_elgamal_params() {
  register_pair.p = BN_new();
  register_pair.g = BN_new();
  register_pair.pk_PKE = BN_new();
  register_pair.phi = BN_new();

  listen_thread_exit = 0;
  int *arg = malloc(sizeof(int));
  if (!arg)
    return 0;
  *arg = sys_params.parties[1].port;

  listen_thread(arg);

  return 1;
}

void free_register_pair() {
  if (register_pair.g) {
    BN_free(register_pair.g);
  }
  if (register_pair.p) {
    BN_free(register_pair.p);
  }
  if (register_pair.pk_PKE) {
    BN_free(register_pair.pk_PKE);
  }
  if (register_pair.phi) {
    BN_free(register_pair.phi);
  }
}
