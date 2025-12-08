#include "sign.h"

Party party = {0};
int offline_id = -1;

int init_party() {
  party.a = EC_POINT_new(sys_params.group);
  party.b = EC_POINT_new(sys_params.group);
  party.delta_i = EC_POINT_new(sys_params.group);
  party.rw_i = EC_POINT_new(sys_params.group);
  party.L_i = EC_POINT_new(sys_params.group);
  party.M_i = EC_POINT_new(sys_params.group);
  party.N_i = EC_POINT_new(sys_params.group);

  party.beta_i = BN_new();
  party.sigma_i = BN_new();

  if (!party.a || !party.b || !party.delta_i || !party.rw_i || !party.L_i ||
      !party.M_i || !party.N_i || !party.beta_i || !party.sigma_i) {
    return 0;
  }

  return 1;
}

void sign_message_handler(const NetworkMessage *msg) {
  if (!msg)
    return;

  int type = msg->type;

  switch (type) {
  case REQUEST_SIGN: {

    char a_hex[128] = {0};
    char b_hex[128] = {0};

    memcpy(a_hex, msg->data, 128);
    memcpy(b_hex, msg->data + 128, 128);
    party.a = deserialize_ec_point(a_hex);
    party.b = deserialize_ec_point(b_hex);

    sign_flag = 1;

    break;
  }
  case SIGNAL_OFFLINE: {
    offline_id = atoi(msg->data);
    sign_flag = 1;
    break;
  }
  case MSG_C2P_L: {
    char L[128] = {0};
    memcpy(L, msg->data, 128);
    party.L_i = deserialize_ec_point(L);

    received = 1;

    break;
  }
  case MSG_C2P_CT: {
    unsigned char *ct = (unsigned char *)msg->data;

    // 解密
    unsigned char key[32];

    memcpy(key, party.key_i, 32);

    unsigned char plaintext[1024];
    int pt_len = Dec(key, ct, plaintext);

    printf("[+] Decrypted message: %.*s\n", pt_len, plaintext);

    unsigned int H_len;

    EVP_Digest(plaintext, pt_len, party.H_msg, &H_len, sys_params.H_sig, NULL);

    received = 1;
    break;
  }
  default: {
    printf("message type error\n");
  }
  }
};

int step2() {
  //生成beta，计算rw、delta
  BIGNUM *beta = BN_new();
  EC_POINT *delta = EC_POINT_new(sys_params.group);
  EC_POINT *rw = EC_POINT_new(sys_params.group);

  if (!random_in_Zq_star(beta)) {
    return 0;
  }

  if (!EC_POINT_mul(sys_params.group, delta, NULL, presign_data.Gamma, beta,
                    NULL)) {
    return 0;
  }

  party.beta_i = BN_dup(beta);
  if (!EC_POINT_copy(party.delta_i, delta)) {
    return 0;
  }

  if (!EC_POINT_mul(sys_params.group, rw, NULL, presign_data.sw, beta, NULL)) {
    return 0;
  }

  if (!EC_POINT_copy(party.rw_i, rw)) {
    return 0;
  }

  //发送delta
  char buffer[128] = {0};

  serialize_ec_point(buffer, delta);

  int party_id = 0;
  const char *ip = sys_params.parties[party_id].ip;
  int port = sys_params.parties[party_id].port;

  send_message(sys_params.current_party_id, ip, port, MSG_P2C_DELTA, buffer);

  BN_free(beta);
  EC_POINT_free(delta);
  EC_POINT_free(rw);

  return 1;
}

int step4() {
  BN_CTX *ctx = BN_CTX_new();

  //随机生成v
  BIGNUM *v = BN_new();
  if (!random_in_Zq(v)) {
    return 0;
  }

  //计算M
  EC_POINT *M = EC_POINT_new(sys_params.group);
  BIGNUM *rw_hash = BN_new();

  if (!H3(party.rw_i, rw_hash)) {
    return 0;
  }

  if (!EC_POINT_mul(sys_params.group, M, v, party.b, rw_hash, ctx)) {
    return 0;
  }

  party.M_i = EC_POINT_dup(M, sys_params.group);

  //计算(a^rw)的逆元
  EC_POINT *temp = EC_POINT_new(sys_params.group);
  if (!EC_POINT_mul(sys_params.group, temp, NULL, party.a, rw_hash, ctx)) {
    return 0;
  }
  if (!EC_POINT_invert(sys_params.group, temp, ctx)) {
    return 0;
  }

  //计算N
  if (!EC_POINT_add(sys_params.group, temp, temp, party.L_i, ctx)) {
    return 0;
  }
  if (!EC_POINT_mul(sys_params.group, party.N_i, NULL, temp, v, ctx)) {
    return 0;
  }

  //计算key_i = H2(rw_i, id_C, id_P, L_i, M_i, N_i)
  unsigned char hash_input[1024];
  unsigned char hash_output[SHA256_DIGEST_LENGTH];
  size_t offset = 0;

  // 序列化 rw_i
  size_t rw_len = EC_POINT_point2oct(
      sys_params.group, party.rw_i, POINT_CONVERSION_COMPRESSED,
      hash_input + offset, sizeof(hash_input) - offset, ctx);
  offset += rw_len;

  // 序列化 id_C (coordinator identifier)
  char id_C = (char)0;
  hash_input[offset] = id_C;
  offset += 1;

  // 序列化 id_P (当前参与方identifier)
  char id_P = (char)sys_params.current_party_id;
  hash_input[offset] = id_P;
  offset += 1;

  // 序列化 L_i
  size_t L_len = EC_POINT_point2oct(
      sys_params.group, party.L_i, POINT_CONVERSION_COMPRESSED,
      hash_input + offset, sizeof(hash_input) - offset, ctx);
  offset += L_len;

  // 序列化 M_i
  size_t M_len = EC_POINT_point2oct(
      sys_params.group, party.M_i, POINT_CONVERSION_COMPRESSED,
      hash_input + offset, sizeof(hash_input) - offset, ctx);
  offset += M_len;

  // 序列化 N_i
  size_t N_len = EC_POINT_point2oct(
      sys_params.group, party.N_i, POINT_CONVERSION_COMPRESSED,
      hash_input + offset, sizeof(hash_input) - offset, ctx);
  offset += N_len;

  // 计算H2哈希
  if (!H2(hash_input, offset, hash_output)) {
    return 0;
  }

  memcpy(party.key_i, hash_output, 32);

  //发送M
  char buffer[128];
  int port = sys_params.parties[0].port;
  char *ip = sys_params.parties[0].ip;

  serialize_ec_point(buffer, M);

  send_message(sys_params.current_party_id, ip, port, MSG_P2C_M, buffer);

  BN_CTX_free(ctx);
  EC_POINT_free(M);
  BN_free(v);
  BN_free(rw_hash);
  return 1;
};

int step7() {
  BN_CTX *ctx = BN_CTX_new();

  //计算w，需要判断上家是否离线
  BIGNUM *bn_H = BN_new();
  BN_bin2bn(party.H_msg, 32, bn_H);

  if (BN_num_bits(bn_H) > BN_num_bits(sys_params.q)) {
    BN_CTX *ctx_temp = BN_CTX_new();
    BN_mod(bn_H, bn_H, sys_params.q, ctx_temp);
    BN_CTX_free(ctx_temp);
  }

  BIGNUM *w = BN_new();
  BIGNUM *u = BN_new();
  BIGNUM *m_phi = BN_new();
  BIGNUM *r_v = BN_new();
  if (offline_id != -1 &&
      (offline_id + 1) % NUM_PARTIES == sys_params.current_party_id) {
    // i-1离线
    BIGNUM *temp = BN_new();
    BN_mod_add(temp, presign_data.phi, presign_data.pre_phi, sys_params.q, ctx);
    BN_mod_mul(m_phi, bn_H, temp, sys_params.q, ctx);
    BN_mod_add(temp, presign_data.v, presign_data.pre_v, sys_params.q, ctx);
    BN_mod_mul(r_v, presign_data.r, temp, sys_params.q, ctx);
    BN_mod_add(w, m_phi, r_v, sys_params.q, ctx);
    BN_mod_add(u, presign_data.u, presign_data.pre_u, sys_params.q, ctx);
  } else {
    // 其他离线或都在线
    BN_mod_mul(m_phi, bn_H, presign_data.phi, sys_params.q, ctx);
    BN_mod_mul(r_v, presign_data.r, presign_data.v, sys_params.q, ctx);
    BN_mod_add(w, m_phi, r_v, sys_params.q, ctx);
    u = BN_dup(presign_data.u);
  }
  // 获取w和u的字节表示
  int w_len = BN_num_bytes(w);
  int u_len = BN_num_bytes(u);

  unsigned char *w_bytes = malloc(w_len);
  unsigned char *u_bytes = malloc(u_len);
  if (!w_bytes || !u_bytes) {
    return 0;
  }

  BN_bn2bin(w, w_bytes);
  BN_bn2bin(u, u_bytes);

  unsigned char key[32];
  memcpy(key, party.key_i, 32);

  // 准备要加密的数据：w_len + w + u_len + u
  size_t plaintext_len = 4 + w_len + 4 + u_len;
  unsigned char *plaintext = malloc(plaintext_len);
  if (!plaintext) {
    return 0;
  }

  // 写入w的长度和值
  uint32_t w_len_net = htonl(w_len);
  memcpy(plaintext, &w_len_net, 4);
  memcpy(plaintext + 4, w_bytes, w_len);

  // 写入u的长度和值
  uint32_t u_len_net = htonl(u_len);
  memcpy(plaintext + 4 + w_len, &u_len_net, 4);
  memcpy(plaintext + 4 + w_len + 4, u_bytes, u_len);

  // 加密
  size_t ct_len = 16 + ((plaintext_len / 16) + 1) * 16;
  unsigned char *ct = malloc(ct_len);
  if (!ct) {
    return 0;
  }

  int out_len = Enc(key, plaintext, plaintext_len, ct);
  if (out_len <= 0) {
    return 0;
  }

  // 分配发送buffer，包含长度前缀
  size_t send_len = 4 + out_len;
  unsigned char *send_buf = malloc(send_len);
  if (!send_buf) {
    return 0;
  }

  // 写入4字节长度
  uint32_t L = htonl(out_len);
  memcpy(send_buf, &L, 4);
  memcpy(send_buf + 4, ct, out_len);

  // 向coordinator发送密文
  int port = sys_params.parties[0].port;
  const char *ip = sys_params.parties[0].ip;
  send_message(sys_params.current_party_id, ip, port, MSG_P2C_SIGMA,
               (const char *)send_buf);

  free(w_bytes);
  free(u_bytes);
  free(plaintext);
  free(ct);
  free(send_buf);
  BN_free(bn_H);
  BN_free(m_phi);
  BN_free(r_v);
  BN_free(w);
  BN_CTX_free(ctx);

  return 1;
}

void free_party() {
  // 释放EC_POINT类型的成员
  if (party.a) {
    EC_POINT_free(party.a);
    party.a = NULL;
  }
  if (party.b) {
    EC_POINT_free(party.b);
    party.b = NULL;
  }
  if (party.delta_i) {
    EC_POINT_free(party.delta_i);
    party.delta_i = NULL;
  }
  if (party.rw_i) {
    EC_POINT_free(party.rw_i);
    party.rw_i = NULL;
  }
  if (party.L_i) {
    EC_POINT_free(party.L_i);
    party.L_i = NULL;
  }
  if (party.M_i) {
    EC_POINT_free(party.M_i);
    party.M_i = NULL;
  }
  if (party.N_i) {
    EC_POINT_free(party.N_i);
    party.N_i = NULL;
  }

  // 释放BIGNUM类型的成员
  if (party.beta_i) {
    BN_free(party.beta_i);
    party.beta_i = NULL;
  }
  if (party.sigma_i) {
    BN_free(party.sigma_i);
    party.sigma_i = NULL;
  }
}
