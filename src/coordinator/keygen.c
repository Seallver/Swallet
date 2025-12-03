#include "keygen.h"

EC_POINT *VK = NULL;
int VK_received_count = 0;

void print_vk(EC_POINT *vk) {
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();

  if (EC_POINT_get_affine_coordinates(sys_params.group, vk, x, y, NULL)) {
    char *x_hex = BN_bn2hex(x);
    char *y_hex = BN_bn2hex(y);

    printf("VK :\n");
    printf("  x = %s\n", x_hex);
    printf("  y = %s\n", y_hex);

    OPENSSL_free(x_hex);
    OPENSSL_free(y_hex);
  }

  BN_free(x);
  BN_free(y);
}

void keygen_message_handler(const NetworkMessage *msg) {
  if (!msg)
    return;

  int type = msg->type;

  switch (type) {
  //接收到coordinator发来的预签名材料
  case MSG_PUBLIC_VK: {
    EC_POINT *VK_i = EC_POINT_new(sys_params.group);
    VK_i = deserialize_ec_point(msg->data);

    EC_POINT_add(sys_params.group, VK, VK, VK_i, NULL);
    VK_received_count += 1;
    if (VK_received_count >= NUM_PARTIES) {
      listen_thread_exit = 1;
      print_vk(VK);
    }
    break;
  }
  default: {
    printf("message type error\n");
  }
  }
}

int recv_VK() {
  listen_thread_exit = 0;
  int *arg = malloc(sizeof(int));
  if (!arg)
    return 0;
  *arg = sys_params.parties[0].port;

  listen_thread(arg);

  return 1;
}
