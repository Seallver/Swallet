#include "presign.h"
#include <openssl/bn.h>

EC_POINT *R = NULL;
int R_received_count = 0;

int send_to_parties() {
  BIGNUM *alpha = BN_new();
  BIGNUM *h = BN_new();
  for (int i = 1; i <= NUM_PARTIES; i++) {
    char buffer[256] = {0};

    EC_POINT *Gamma_i = EC_POINT_new(sys_params.group);

    EC_POINT *sw_i = EC_POINT_new(sys_params.group);

    if (!random_in_Zq_star(alpha)) {
      return 0;
    }

    if (!EC_POINT_mul(sys_params.group, Gamma_i, alpha, NULL, NULL, NULL)) {
      return 0;
    }

    if (!H1((const unsigned char *)PASSWORD, strlen(PASSWORD), h)) {
      return 0;
    }

    if (!EC_POINT_mul(sys_params.group, sw_i, NULL, Gamma_i, h, NULL)) {
      return 0;
    }

    serialize_ec_point(buffer, Gamma_i);
    serialize_ec_point(buffer + 128, sw_i);

    int party_id = i;
    const char *ip = sys_params.parties[party_id].ip;
    int port = sys_params.parties[party_id].port;

    if (!send_message(0, ip, port, MSG_PRESIGN_DATA, buffer)) {
      return 0;
    }
  }
  BN_free(alpha);
  BN_free(h);
  return 1;
}

void presign_message_handler(const NetworkMessage *msg) {
  if (!msg)
    return;

  int type = msg->type;

  switch (type) {
  //接收到coordinator发来的预签名材料
  case MSG_PUBLIC_R: {
    EC_POINT *R_i = EC_POINT_new(sys_params.group);
    R_i = deserialize_ec_point(msg->data);

    EC_POINT_add(sys_params.group, R, R, R_i, NULL);
    R_received_count += 1;
    if (R_received_count >= NUM_PARTIES) {
      listen_thread_exit = 1;
    }
    break;
  }
  default: {
    printf("message type error\n");
  }
  }
}

int recv_R() {
  listen_thread_exit = 0;
  int *arg = malloc(sizeof(int));
  if (!arg)
    return 0;
  *arg = sys_params.parties[0].port;

  listen_thread(arg);

  return 1;
}
