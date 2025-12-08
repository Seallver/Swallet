#include "presign.h"

PresignData presign_data = {0};
RecvData recv_data = {0};

int init_presign() {
  presign_data.Gamma = EC_POINT_new(sys_params.group);
  presign_data.sw = EC_POINT_new(sys_params.group);
  presign_data.R = EC_POINT_new(sys_params.group);
  presign_data.sum_R = EC_POINT_new(sys_params.group);

  presign_data.k = BN_new();
  presign_data.phi = BN_new();
  presign_data.x = BN_new();
  presign_data.r = BN_new();
  presign_data.u = BN_new();
  presign_data.v = BN_new();
  presign_data.pre_u = BN_new();
  presign_data.pre_phi = BN_new();
  presign_data.pre_v = BN_new();

  if (presign_data.Gamma == NULL || presign_data.sw == NULL ||
      presign_data.R == NULL || presign_data.sum_R == NULL ||
      presign_data.k == NULL || presign_data.phi == NULL ||
      presign_data.x == NULL || presign_data.r == NULL ||
      presign_data.u == NULL || presign_data.v == NULL ||
      presign_data.pre_u == NULL || presign_data.pre_phi == NULL ||
      presign_data.pre_v == NULL) {
    return 0;
  }

  recv_data.Gamma = EC_POINT_new(sys_params.group);
  recv_data.sw = EC_POINT_new(sys_params.group);

  recv_data.pre_k = BN_new();
  recv_data.pre_phi = BN_new();
  recv_data.pre_x = BN_new();
  recv_data.pre_u = BN_new();
  recv_data.pre_v = BN_new();

  if (recv_data.Gamma == NULL || recv_data.sw == NULL ||
      recv_data.pre_k == NULL || recv_data.pre_phi == NULL ||
      recv_data.pre_x == NULL || recv_data.pre_u == NULL ||
      recv_data.pre_v == NULL) {
    return 0;
  }

  return 1;
}

void presign_message_handler(const NetworkMessage *msg) {
  if (!msg)
    return;

  int type = msg->type;

  switch (type) {
  //接收到coordinator发来的预签名材料
  case MSG_PRESIGN_DATA: {
    char gamma_hex[128] = {0};
    char sw_hex[128] = {0};

    memcpy(gamma_hex, msg->data, 128);
    memcpy(sw_hex, msg->data + 128, 128);
    recv_data.Gamma = deserialize_ec_point(gamma_hex);
    recv_data.sw = deserialize_ec_point(sw_hex);

    if (!recv_data.Gamma || !recv_data.sw) {
      printf("[-] Deserialization failed\n");
    }

    printf("[+] Received coordinator data:\n");
    printf("    Gamma_i = %.128s\n", gamma_hex);
    printf("    sw_i    = %.128s\n", sw_hex);

    presign_data.Gamma = deserialize_ec_point(gamma_hex);
    presign_data.sw = deserialize_ec_point(sw_hex);

    recv_data.received = 1;
    break;
  }
  //接收到上家的签名材料
  case MSG_KEY_EXCHANGE: {
    BIGNUM *k = NULL, *phi = NULL, *x = NULL;

    k = deserialize_bn(msg->data);
    phi = deserialize_bn(msg->data + 64);
    x = deserialize_bn(msg->data + 128);

    recv_data.pre_k = BN_dup(k);
    recv_data.pre_phi = BN_dup(phi);
    recv_data.pre_x = BN_dup(x);

    if (!recv_data.pre_k || !recv_data.pre_phi || !recv_data.pre_x) {
      printf("[-] Deserialization failed\n");
    }

    recv_data.received = 1;
    break;
  }
  //接收到上家的uv
  case MSG_UV_DATA: {
    BIGNUM *u = NULL, *v = NULL;
    u = deserialize_bn(msg->data);
    v = deserialize_bn(msg->data + 64);

    recv_data.pre_u = BN_dup(u);
    recv_data.pre_v = BN_dup(v);

    if (!recv_data.pre_u || !recv_data.pre_v) {
      printf("[-] Deserialization failed\n");
    }

    recv_data.received = 1;
    break;
  }
    //接到公共参数R
  case MSG_PUBLIC_R: {
    EC_POINT *R_i = EC_POINT_new(sys_params.group);
    R_i = deserialize_ec_point(msg->data);

    EC_POINT_add(sys_params.group, presign_data.sum_R, presign_data.sum_R, R_i,
                 NULL);
    recv_data.R_received += 1;
    break;
  }
  default: {
    printf("message type error\n");
  }
  }
}

int send_k_phi_x() {
  BN_CTX *ctx = BN_CTX_new();
  if (!ctx) {
    fprintf(stderr, "Failed to create BN context\n");
    return 0;
  }

  //随机生成k、phi
  if (!random_in_Zq_star(presign_data.k) ||
      !random_in_Zq_star(presign_data.phi)) {
    fprintf(stderr, "Failed to generate secret share\n");
    BN_CTX_free(ctx);
    return 0;
  }

  int myid = sys_params.current_party_id;
  int party_id = myid == NUM_PARTIES ? 1 : myid + 1;
  const char *ip = sys_params.parties[party_id].ip;
  int port = sys_params.parties[party_id].port;

  char buffer[192] = {0}; // 3 * 64 bytes

  serialize_bn(buffer, presign_data.k);
  serialize_bn(buffer + 64, presign_data.phi);
  serialize_bn(buffer + 128, presign_data.x);

  send_message(sys_params.current_party_id, ip, port, MSG_KEY_EXCHANGE, buffer);

  return 1;
}

int public_R() {
  //计算R
  if (!EC_POINT_mul(sys_params.group, presign_data.R, presign_data.k, NULL,
                    NULL, NULL)) {
    return 0;
  }
  presign_data.sum_R = EC_POINT_dup(presign_data.R, sys_params.group);

  //广播R
  char buffer[128];
  serialize_ec_point(buffer, presign_data.R);
  broadcast(MSG_PUBLIC_R, buffer);

  return 1;
}

int compute_u_v() {
  //发送数据
  if (!send_k_phi_x()) {
    perror("send_message");
    return 0;
  }

  //等待接收完毕
  while (1) {
    if (recv_data.received) {
      recv_data.received = 0;
      break;
    }
  }

  presign_data.pre_phi = BN_dup(recv_data.pre_phi);

  //计算u、v
  BN_CTX *ctx = BN_CTX_new();
  if (!ctx)
    return 0;

  //计算k_i*φ_i
  if (!BN_mod_mul(presign_data.u, presign_data.k, presign_data.phi,
                  sys_params.q, ctx))
    goto error;

  BIGNUM *temp1 = BN_new();
  BIGNUM *temp2 = BN_new();
  if (!temp1 || !temp2)
    goto error;

  //计算k_i*φ_i-1
  if (!BN_mod_mul(temp1, presign_data.k, recv_data.pre_phi, sys_params.q, ctx))
    goto error;
  if (!BN_mod_add(presign_data.u, presign_data.u, temp1, sys_params.q, ctx))
    goto error;

  // 计算 k_i-1*φ_i
  if (!BN_mod_mul(temp1, recv_data.pre_k, presign_data.phi, sys_params.q, ctx))
    goto error;
  if (!BN_mod_add(presign_data.u, presign_data.u, temp1, sys_params.q, ctx))
    goto error;

  // 计算 x_i*φ_i
  if (!BN_mod_mul(presign_data.v, presign_data.x, presign_data.phi,
                  sys_params.q, ctx))
    goto error;

  // 计算 x_i*φ_i-1
  if (!BN_mod_mul(temp1, presign_data.x, recv_data.pre_phi, sys_params.q, ctx))
    goto error;
  if (!BN_mod_add(presign_data.v, presign_data.v, temp1, sys_params.q, ctx))
    goto error;

  // 计算 x_i-1*φ_i
  if (!BN_mod_mul(temp1, recv_data.pre_x, presign_data.phi, sys_params.q, ctx))
    goto error;
  if (!BN_mod_add(presign_data.v, presign_data.v, temp1, sys_params.q, ctx))
    goto error;

  BN_free(temp1);
  BN_free(temp2);

  BN_CTX_free(ctx);
  return 1;

error:
  if (ctx)
    BN_CTX_free(ctx);
  return 0;
}

int exchange_u_v() {
  //发送数据
  if (!send_u_v(presign_data)) {
    perror("send_message");
    return 0;
  }

  //等待接收完毕
  while (1) {
    if (recv_data.received) {
      recv_data.received = 0;
      break;
    }
  }

  presign_data.pre_u = BN_dup(recv_data.pre_u);
  presign_data.pre_v = BN_dup(recv_data.pre_v);

  return 1;
}

int send_u_v() {
  BN_CTX *ctx = BN_CTX_new();
  if (!ctx) {
    fprintf(stderr, "Failed to create BN context\n");
    return 0;
  }

  int myid = sys_params.current_party_id;
  int party_id = myid == NUM_PARTIES ? 1 : myid + 1;
  const char *ip = sys_params.parties[party_id].ip;
  int port = sys_params.parties[party_id].port;

  char buffer[128] = {0}; // 2 * 64 bytes

  if (presign_data.u)
    serialize_bn(buffer, presign_data.u);
  if (presign_data.v)
    serialize_bn(buffer + 64, presign_data.v);

  send_message(myid, ip, port, MSG_UV_DATA, buffer);

  return 1;
}

void free_presigndata() {
  // EC_POINT
  if (presign_data.Gamma) {
    EC_POINT_free(presign_data.Gamma);
    presign_data.Gamma = NULL;
  }
  if (presign_data.sw) {
    EC_POINT_free(presign_data.sw);
    presign_data.sw = NULL;
  }
  if (presign_data.R) {
    EC_POINT_free(presign_data.R);
    presign_data.R = NULL;
  }
  if (presign_data.sum_R) {
    EC_POINT_free(presign_data.sum_R);
    presign_data.sum_R = NULL;
  }

  // BIGNUM
  if (presign_data.k) {
    BN_free(presign_data.k);
    presign_data.k = NULL;
  }
  if (presign_data.phi) {
    BN_free(presign_data.phi);
    presign_data.phi = NULL;
  }
  if (presign_data.x) {
    BN_free(presign_data.x);
    presign_data.x = NULL;
  }
  if (presign_data.u) {
    BN_free(presign_data.u);
    presign_data.u = NULL;
  }
  if (presign_data.v) {
    BN_free(presign_data.v);
    presign_data.v = NULL;
  }
  if (presign_data.r) {
    BN_free(presign_data.r);
    presign_data.r = NULL;
  }
}

void free_recvdata() {
  if (recv_data.pre_k) {
    BN_free(recv_data.pre_k);
    recv_data.pre_k = NULL;
  }
  if (recv_data.pre_phi) {
    BN_free(recv_data.pre_phi);
    recv_data.pre_phi = NULL;
  }
  if (recv_data.pre_x) {
    BN_free(recv_data.pre_x);
    recv_data.pre_x = NULL;
  }

  if (recv_data.pre_u) {
    BN_free(recv_data.pre_u);
    recv_data.pre_u = NULL;
  }

  if (recv_data.pre_v) {
    BN_free(recv_data.pre_v);
    recv_data.pre_v = NULL;
  }

  recv_data.received = 0;
  recv_data.R_received = 0;
}