#include "keygen.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

key_pair_t key_pair = {0};

void keygen_message_handler(const NetworkMessage *msg) {
  if (!msg)
    return;

  int type = msg->type;

  switch (type) {
  case DATA_SK_PK: {
    key_pair.sk_s = deserialize_bn(msg->data);
    key_pair.pk = deserialize_ec_point(msg->data + 64);
    listen_thread_exit = 1;

    break;
  }
  default: {
    printf("message type error\n");
  }
  }
}

int recv_sk_pk() {
  key_pair.pk = EC_POINT_new(sys_params.group);
  key_pair.sk_s = BN_new();

  listen_thread_exit = 0;
  int *arg = malloc(sizeof(int));
  if (!arg)
    return 0;
  *arg = sys_params.parties[0].port;

  listen_thread(arg);

  return 1;
}

void free_key_pair() {
  if (key_pair.sk_s) {
    BN_free(key_pair.sk_s);
    key_pair.sk_s = NULL;
  }
  if (key_pair.pk) {
    EC_POINT_free(key_pair.pk);
    key_pair.pk = NULL;
  }
}
