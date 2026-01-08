#include "keygen.h"

key_pair_t key_pair = {0};

int vk_received_count = 0;

int generate_key_pair() {
  if (!sys_params.group || !sys_params.q) {
    fprintf(stderr, "Invalid parameters\n");
    return 0;
  }

  key_pair.secret_share = BN_new();
  key_pair.public_share = EC_POINT_new(sys_params.group);
  key_pair.vk = EC_POINT_new(sys_params.group);

  if (!key_pair.secret_share || !key_pair.public_share) {
    fprintf(stderr, "Memory allocation failed\n");
    free_key_pair(key_pair);
    return 0;
  }

  BN_CTX *ctx = BN_CTX_new();
  if (!ctx) {
    fprintf(stderr, "Failed to create BN context\n");
    free_key_pair(key_pair);
    return 0;
  }

  //随机生成私钥
  if (!random_in_Zq_star(key_pair.secret_share)) {
    fprintf(stderr, "Failed to generate secret share\n");
    BN_CTX_free(ctx);
    free_key_pair(key_pair);
    return 0;
  }

  //计算公钥
  if (!EC_POINT_mul(sys_params.group, key_pair.public_share,
                    key_pair.secret_share, NULL, NULL, ctx)) {
    fprintf(stderr, "Failed to compute public share g^{x_i}\n");
    BN_CTX_free(ctx);
    free_key_pair(key_pair);
    return 0;
  }

  //验证公钥是否合法
  if (!EC_POINT_is_on_curve(sys_params.group, key_pair.public_share, ctx)) {
    fprintf(stderr, "Generated public share is not on the curve\n");
    BN_CTX_free(ctx);
    free_key_pair(key_pair);
    return 0;
  }

  BN_CTX_free(ctx);
  return 1;
}

void keygen_message_handler(const NetworkMessage *msg) {
  if (!msg)
    return;

  int type = msg->type;

  switch (type) {
    //接到公共参数vk
  case MSG_PUBLIC_VK: {
    EC_POINT *VK_i = EC_POINT_new(sys_params.group);
    VK_i = deserialize_ec_point(msg->data);

    EC_POINT_add(sys_params.group, key_pair.vk, key_pair.vk, VK_i, NULL);
    vk_received_count += 1;
    EC_POINT_free(VK_i);
    break;
  }
  default: {
    printf("message type error\n");
  }
  }
}

int public_VK() {
  //广播vk
  char buffer[128];
  serialize_ec_point(buffer, key_pair.public_share);
  broadcast(MSG_PUBLIC_VK, buffer);

  return 1;
}

void free_key_pair() {
  if (key_pair.secret_share) {
    BN_free(key_pair.secret_share);
    key_pair.secret_share = NULL;
  }
  if (key_pair.public_share) {
    EC_POINT_free(key_pair.public_share);
    key_pair.public_share = NULL;
  }
  if (key_pair.vk) {
    EC_POINT_free(key_pair.vk);
    key_pair.vk = NULL;
  }
}
