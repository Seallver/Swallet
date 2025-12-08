#include "sign.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

Coordinator coord = {0};
int offline_id = -1;
int online_count = NUM_PARTIES;
int received = 0;

int init_coordinator() {
  int party_count = NUM_PARTIES + 1;

  // 分配指针数组内存
  coord.delta_i = (EC_POINT **)malloc(party_count * sizeof(EC_POINT *));
  coord.rw_i_prime = (EC_POINT **)malloc(party_count * sizeof(EC_POINT *));
  coord.L_i = (EC_POINT **)malloc(party_count * sizeof(EC_POINT *));
  coord.M_i = (EC_POINT **)malloc(party_count * sizeof(EC_POINT *));
  coord.N_i_prime = (EC_POINT **)malloc(party_count * sizeof(EC_POINT *));
  coord.mu_i = (BIGNUM **)malloc(party_count * sizeof(BIGNUM *));
  coord.u_i = (BIGNUM **)malloc(party_count * sizeof(BIGNUM *));
  coord.w_i = (BIGNUM **)malloc(party_count * sizeof(BIGNUM *));

  coord.a = EC_POINT_new(sys_params.group);
  coord.b = EC_POINT_new(sys_params.group);

  coord.s = BN_new();
  coord.r = BN_new();

  // 初始化所有指针
  for (int i = 0; i < party_count; i++) {
    coord.key_i_prime[i] = malloc(32); // 每个元素分配32字节
    if (!coord.key_i_prime[i]) {
      printf("Memory allocation failed for key_i_prime[%d]\n", i);
      return -1;
    }
    memset(coord.key_i_prime[i], 0, 32); // 初始化为0
  }

  if (!coord.delta_i || !coord.rw_i_prime || !coord.L_i || !coord.M_i ||
      !coord.N_i_prime || !coord.mu_i || !coord.u_i || !coord.w_i || !coord.a ||
      !coord.b || !coord.s || !coord.r) {
    printf("Memory allocation failed for arrays\n");
    return -1;
  }

  // 初始化所有指针为NULL
  for (int i = 0; i < party_count; i++) {
    coord.mu_i[i] = BN_new();
    coord.delta_i[i] = EC_POINT_new(sys_params.group);
    coord.rw_i_prime[i] = EC_POINT_new(sys_params.group);
    coord.L_i[i] = EC_POINT_new(sys_params.group);
    coord.M_i[i] = EC_POINT_new(sys_params.group);
    coord.N_i_prime[i] = EC_POINT_new(sys_params.group);
    coord.w_i[i] = BN_new();
    coord.u_i[i] = BN_new();
  }

  return 1;
}

void sign_message_handler(const NetworkMessage *msg) {
  if (!msg)
    return;

  int type = msg->type;
  int party_id = msg->src_id;

  // 验证参与者ID在有效范围内
  if (party_id <= 0 || party_id > NUM_PARTIES) {
    printf("Invalid participant ID: %d\n", party_id);
    return;
  }

  switch (type) {
  case MSG_P2C_DELTA: {
    EC_POINT *Delta = EC_POINT_new(sys_params.group);
    Delta = deserialize_ec_point(msg->data);
    coord.delta_i[party_id] = EC_POINT_dup(Delta, sys_params.group);
    received += 1;
    break;
  }
  case MSG_P2C_M: {
    EC_POINT *M = EC_POINT_new(sys_params.group);
    M = deserialize_ec_point(msg->data);
    coord.M_i[party_id] = EC_POINT_dup(M, sys_params.group);
    received += 1;
    break;
  }
  case MSG_P2C_SIGMA: {
    // 密文所在位置
    unsigned char *ct = (unsigned char *)msg->data;

    // 解密
    unsigned char key[32];

    memcpy(key, coord.key_i_prime[party_id], 32);

    size_t max_pt_len = 1024;
    unsigned char *plaintext = malloc(max_pt_len);
    if (!plaintext) {
      return;
    }

    int pt_len = Dec(key, ct, plaintext);
    if (pt_len <= 0) {
      printf("Dec failed pt_len:%d\n", pt_len);
      free(plaintext);
      return;
    }

    // 解析解密后的数据：w_len(4字节) + w + u_len(4字节) + u
    unsigned char *ptr = plaintext;

    uint32_t w_len;
    memcpy(&w_len, ptr, 4);
    w_len = ntohl(w_len);
    ptr += 4;

    if (ptr + w_len > plaintext + pt_len) {
      free(plaintext);
      return;
    }

    BIGNUM *w = BN_new();
    BN_bin2bn(ptr, w_len, w);
    ptr += w_len;

    uint32_t u_len;
    memcpy(&u_len, ptr, 4);
    u_len = ntohl(u_len);
    ptr += 4;

    if (ptr + u_len > plaintext + pt_len) {
      free(plaintext);
      return;
    }

    BIGNUM *u = BN_new();
    BN_bin2bn(ptr, u_len, u);

    coord.w_i[party_id] = BN_dup(w);
    coord.u_i[party_id] = BN_dup(u);

    BN_free(w);
    BN_free(u);

    received += 1;
    break;
  }
  default: {
    printf("message type error\n");
  }
  }
};

int step1() {
  //随机生成a、b用于签名
  EC_POINT *a = EC_POINT_new(sys_params.group);
  EC_POINT *b = EC_POINT_new(sys_params.group);
  if (!random_in_Group(a) || !random_in_Group(b)) {
    return 0;
  }

  coord.a = EC_POINT_dup(a, sys_params.group);
  coord.b = EC_POINT_dup(b, sys_params.group);

  char buffer[256] = {0};
  serialize_ec_point(buffer, a);
  serialize_ec_point(buffer + 128, b);

  for (int i = 1; i <= NUM_PARTIES; i++) {
    if (i == offline_id)
      continue;
    int party_id = i;
    const char *ip = sys_params.parties[party_id].ip;
    int port = sys_params.parties[party_id].port;

    if (!send_message(0, ip, port, REQUEST_SIGN, buffer)) {
      if (offline_id != -1) {
        printf("too many parties are offline\n");
        return 0;
      } else {
        offline_id = i;
        online_count -= 1;
      }
    };
  }

  EC_POINT_free(a);
  EC_POINT_free(b);
  return 1;
}

int broadcast_offline() {
  char buffer[32];

  // 将 offline_id 转换为字符串
  snprintf(buffer, sizeof(buffer), "%d", offline_id);

  for (int id = 1; id <= NUM_PARTIES; id++) {
    if (id == offline_id)
      continue;
    int port = sys_params.parties[id].port;
    char *ip = sys_params.parties[id].ip;
    send_message(0, ip, port, SIGNAL_OFFLINE, buffer);
  }

  return 1;
}

int step3() {
  //计算 h'
  BIGNUM *h_prime = BN_new();
  if (!H1((const unsigned char *)PASSWORD_PRIME, strlen(PASSWORD_PRIME),
          h_prime)) {
    return 0;
  }

  // 计算 L_i
  for (int i = 1; i <= NUM_PARTIES; i++) {
    if (i == offline_id)
      continue;
    //随机生成 mu
    BIGNUM *mu = BN_new();
    if (!random_in_Zq(mu)) {
      return 0;
    }

    coord.mu_i[i] = BN_dup(mu);

    //计算rw'
    EC_POINT *delta = EC_POINT_new(sys_params.group);
    delta = EC_POINT_dup(coord.delta_i[i], sys_params.group);
    EC_POINT *rw = EC_POINT_new(sys_params.group);
    if (!EC_POINT_mul(sys_params.group, rw, NULL, delta, h_prime, NULL)) {
      return 0;
    }

    coord.rw_i_prime[i] = EC_POINT_dup(rw, sys_params.group);

    EC_POINT *L = EC_POINT_new(sys_params.group);

    BIGNUM *rw_hash = BN_new();
    if (!H3(rw, rw_hash)) {
      return 0;
    }

    if (!EC_POINT_mul(sys_params.group, L, mu, coord.a, rw_hash, NULL)) {
      return 0;
    }

    coord.L_i[i] = EC_POINT_dup(L, sys_params.group);

    char buffer[128];

    serialize_ec_point(buffer, L);

    const char *ip = sys_params.parties[i].ip;
    int port = sys_params.parties[i].port;

    send_message(0, ip, port, MSG_C2P_L, buffer);

    BN_free(mu);
    BN_free(rw_hash);
    EC_POINT_free(delta);
    EC_POINT_free(rw);
    EC_POINT_free(L);
  }

  BN_free(h_prime);
  return 1;
}

int step5() {
  BN_CTX *ctx = BN_CTX_new();

  for (int id = 1; id <= NUM_PARTIES; id++) {
    if (id == offline_id)
      continue;
    EC_POINT *temp_point = EC_POINT_new(sys_params.group);
    BIGNUM *temp = BN_new();

    //计算rw_hash
    if (!H3(coord.rw_i_prime[id], temp)) {
      return 0;
    }

    //计算b^rw的逆
    if (!EC_POINT_mul(sys_params.group, temp_point, NULL, coord.b, temp, ctx)) {
      return 0;
    }

    if (!EC_POINT_invert(sys_params.group, temp_point, ctx)) {
      return 0;
    }

    //计算N
    if (!EC_POINT_add(sys_params.group, temp_point, temp_point, coord.M_i[id],
                      ctx)) {
      return 0;
    }

    if (!EC_POINT_mul(sys_params.group, coord.N_i_prime[id], NULL, temp_point,
                      coord.mu_i[id], ctx)) {
      return 0;
    }

    //计算key
    unsigned char hash_input[1024];
    unsigned char hash_output[SHA256_DIGEST_LENGTH];
    size_t offset = 0;

    // 序列化 rw_i
    size_t rw_len = EC_POINT_point2oct(
        sys_params.group, coord.rw_i_prime[id], POINT_CONVERSION_COMPRESSED,
        hash_input + offset, sizeof(hash_input) - offset, ctx);
    offset += rw_len;

    // 序列化 id_C (coordinator identifier)
    char id_C = (char)0;
    hash_input[offset] = id_C;
    offset += 1;

    // 序列化 id_P (当前参与方identifier)
    char id_P = (char)id;
    hash_input[offset] = id_P;
    offset += 1;

    // 序列化 L_i
    size_t L_len = EC_POINT_point2oct(
        sys_params.group, coord.L_i[id], POINT_CONVERSION_COMPRESSED,
        hash_input + offset, sizeof(hash_input) - offset, ctx);
    offset += L_len;

    // 序列化 M_i
    size_t M_len = EC_POINT_point2oct(
        sys_params.group, coord.M_i[id], POINT_CONVERSION_COMPRESSED,
        hash_input + offset, sizeof(hash_input) - offset, ctx);
    offset += M_len;

    // 序列化 N_i
    size_t N_len = EC_POINT_point2oct(
        sys_params.group, coord.N_i_prime[id], POINT_CONVERSION_COMPRESSED,
        hash_input + offset, sizeof(hash_input) - offset, ctx);
    offset += N_len;

    // 计算H2哈希
    if (!H2(hash_input, offset, hash_output)) {
      return 0;
    }

    memcpy(coord.key_i_prime[id], hash_output, 32);

    BN_free(temp);
    EC_POINT_free(temp_point);
  }

  BN_CTX_free(ctx);
  return 1;
}

int step6() {
  for (int id = 1; id <= NUM_PARTIES; id++) {
    if (id == offline_id)
      continue;

    unsigned char key[32];
    memcpy(key, coord.key_i_prime[id], 32);

    unsigned char *msg = (unsigned char *)MESSAGE;
    size_t msg_len = strlen(MESSAGE);

    size_t ct_len = 16 + ((msg_len / 16) + 1) * 16;
    unsigned char *ct = malloc(ct_len);
    if (!ct)
      return 0;

    int out_len = Enc(key, msg, msg_len, ct);
    if (out_len <= 0) {
      free(ct);
      return 0;
    }

    // 分配新的 buffer，包含长度前缀
    size_t send_len = 4 + out_len;
    unsigned char *send_buf = malloc(send_len);

    // 写入 4 字节长度
    uint32_t L = htonl(out_len);
    memcpy(send_buf, &L, 4);

    // 写入密文
    memcpy(send_buf + 4, ct, out_len);

    // 发送消息
    int port = sys_params.parties[id].port;
    const char *ip = sys_params.parties[id].ip;
    send_message(0, ip, port, MSG_C2P_CT, (const char *)send_buf);

    free(ct);
    free(send_buf);
  }

  return 1;
}

int step8() {
  //计算s
  BIGNUM *sum_w = BN_new();
  BIGNUM *sum_u = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  for (int id = 1; id <= NUM_PARTIES; id++) {
    if (id == offline_id)
      continue;
    BN_mod_add(sum_u, sum_u, coord.u_i[id], sys_params.q, ctx);
    BN_mod_add(sum_w, sum_w, coord.w_i[id], sys_params.q, ctx);
  }

  BIGNUM *sum_u_inv = BN_new();
  BN_mod_inverse(sum_u_inv, sum_u, sys_params.q, ctx);
  BN_mod_mul(coord.s, sum_w, sum_u_inv, sys_params.q, ctx);

  //计算r
  if (!get_point_x_coordinate(R, coord.r)) {
    printf("compute r failed\n");
    return 0;
  }

  BN_free(sum_w);
  BN_free(sum_u);
  BN_free(sum_u_inv);
  BN_CTX_free(ctx);

  return 1;
}

int verify(const BIGNUM *r, const BIGNUM *s, EC_POINT *vk) {
  EC_GROUP *group = sys_params.group;

  if (!r || !s || !vk) {
    printf("Invalid input parameters\n");
    return 0;
  }

  // 1. 获取曲线参数和阶 n
  const BIGNUM *n = sys_params.q;
  if (!n) {
    printf("Failed to get curve order\n");
    return 0;
  }

  // 2. 检查 r 和 s 的范围 [1, n-1]
  if (BN_is_zero(r) || BN_cmp(r, n) >= 0) {
    printf("Invalid r value (out of range)\n");
    return 0;
  }
  if (BN_is_zero(s) || BN_cmp(s, n) >= 0) {
    printf("Invalid s value (out of range)\n");
    return 0;
  }

  // 3. 计算消息的哈希值
  unsigned char digest[SHA256_DIGEST_LENGTH];
  unsigned int H_len;
  EVP_Digest(MESSAGE, strlen(MESSAGE), digest, &H_len, sys_params.H_sig, NULL);

  // 将哈希值转换为 BIGNUM (e)
  BIGNUM *e = BN_new();
  BN_bin2bn(digest, SHA256_DIGEST_LENGTH, e);

  // 如果哈希值大于 n，需要取模 n
  if (BN_num_bits(e) > BN_num_bits(n)) {
    BN_CTX *ctx_temp = BN_CTX_new();
    BN_mod(e, e, n, ctx_temp);
    BN_CTX_free(ctx_temp);
  }

  // 4. 计算 s 的模逆元 s_inv
  BN_CTX *ctx = BN_CTX_new();
  if (!ctx) {
    printf("Failed to create BN_CTX\n");
    BN_free(e);
    return 0;
  }

  BIGNUM *s_inv = BN_new();
  if (!BN_mod_inverse(s_inv, s, n, ctx)) {
    printf("Failed to compute modular inverse of s\n");
    return 0;
  }

  // 5. 计算 u1 = e * s_inv mod n 和 u2 = r * s_inv mod n
  BIGNUM *u1 = BN_new();
  BIGNUM *u2 = BN_new();

  BN_mod_mul(u1, e, s_inv, n, ctx);
  BN_mod_mul(u2, r, s_inv, n, ctx);

  // 6. 计算点 P = u1 * G + u2 * vk
  EC_POINT *P = EC_POINT_new(group);
  EC_POINT *tmp1 = EC_POINT_new(group);
  EC_POINT *tmp2 = EC_POINT_new(group);

  // tmp1 = u1 * G (基点)
  EC_POINT_mul(group, tmp1, u1, NULL, NULL, ctx);

  // tmp2 = u2 * vk (公钥点)
  EC_POINT_mul(group, tmp2, NULL, vk, u2, ctx);

  // P = tmp1 + tmp2
  EC_POINT_add(group, P, tmp1, tmp2, ctx);

  // 7. 检查 P 是否为无穷远点
  if (EC_POINT_is_at_infinity(group, P)) {
    printf("Resulting point is at infinity\n");
    return 0;
  }

  // 8. 获取点 P 的 x 坐标
  BIGNUM *x_P = BN_new();
  BIGNUM *y_P = BN_new();
  if (!EC_POINT_get_affine_coordinates(group, P, x_P, y_P, ctx)) {
    printf("Failed to get affine coordinates\n");
    return 0;
  }

  // 9. 计算 x_P mod n
  BIGNUM *x_mod_n = BN_new();
  BN_mod(x_mod_n, x_P, n, ctx);

  // 10. 验证 x_mod_n 是否等于 r
  int result = (BN_cmp(x_mod_n, r) == 0);

  if (result) {
    printf("Signature verification SUCCESS\n");
  } else {
    printf("Signature verification FAILED\n");
    printf("  Computed x mod n: ");
    BN_print_fp(stdout, x_mod_n);
    printf("\n  Expected r:       ");
    BN_print_fp(stdout, r);
    printf("\n");
  }

  // 11. 清理所有分配的资源
  EC_POINT_free(P);
  EC_POINT_free(tmp1);
  EC_POINT_free(tmp2);
  BN_free(e);
  BN_free(s_inv);
  BN_free(u1);
  BN_free(u2);
  BN_free(x_P);
  BN_free(y_P);
  BN_free(x_mod_n);
  BN_CTX_free(ctx);

  return result;
}

void free_coordinator() {
  int party_count = NUM_PARTIES + 1;

  if (coord.delta_i) {
    for (int i = 0; i < party_count; i++) {
      if (coord.delta_i[i]) {
        EC_POINT_free(coord.delta_i[i]);
        coord.delta_i[i] = NULL;
      }
    }
  }

  if (coord.rw_i_prime) {
    for (int i = 0; i < party_count; i++) {
      if (coord.rw_i_prime[i]) {
        EC_POINT_free(coord.rw_i_prime[i]);
        coord.rw_i_prime[i] = NULL;
      }
    }
  }

  if (coord.L_i) {
    for (int i = 0; i < party_count; i++) {
      if (coord.L_i[i]) {
        EC_POINT_free(coord.L_i[i]);
        coord.L_i[i] = NULL;
      }
    }
  }

  if (coord.M_i) {
    for (int i = 0; i < party_count; i++) {
      if (coord.M_i[i]) {
        EC_POINT_free(coord.M_i[i]);
        coord.M_i[i] = NULL;
      }
    }
  }

  if (coord.N_i_prime) {
    for (int i = 0; i < party_count; i++) {
      if (coord.N_i_prime[i]) {
        EC_POINT_free(coord.N_i_prime[i]);
        coord.N_i_prime[i] = NULL;
      }
    }
  }

  if (coord.mu_i) {
    for (int i = 0; i < party_count; i++) {
      if (coord.mu_i[i]) {
        BN_free(coord.mu_i[i]);
        coord.mu_i[i] = NULL;
      }
    }
  }

  if (coord.u_i) {
    for (int i = 0; i < party_count; i++) {
      if (coord.u_i[i]) {
        BN_free(coord.u_i[i]);
        coord.u_i[i] = NULL;
      }
    }
  }

  if (coord.w_i) {
    for (int i = 0; i < party_count; i++) {
      if (coord.w_i[i]) {
        BN_free(coord.w_i[i]);
        coord.w_i[i] = NULL;
      }
    }
  }

  for (int i = 0; i < party_count; i++) {
    if (coord.key_i_prime[i]) {
      free(coord.key_i_prime[i]);
      coord.key_i_prime[i] = NULL;
    }
  }

  if (coord.a) {
    EC_POINT_free(coord.a);
    coord.a = NULL;
  }
  if (coord.b) {
    EC_POINT_free(coord.b);
    coord.b = NULL;
  }

  if (coord.s) {
    BN_free(coord.s);
    coord.s = NULL;
  }
  if (coord.r) {
    BN_free(coord.r);
    coord.r = NULL;
  }

  if (coord.delta_i) {
    free(coord.delta_i);
    coord.delta_i = NULL;
  }
  if (coord.rw_i_prime) {
    free(coord.rw_i_prime);
    coord.rw_i_prime = NULL;
  }
  if (coord.L_i) {
    free(coord.L_i);
    coord.L_i = NULL;
  }
  if (coord.M_i) {
    free(coord.M_i);
    coord.M_i = NULL;
  }
  if (coord.N_i_prime) {
    free(coord.N_i_prime);
    coord.N_i_prime = NULL;
  }
  if (coord.mu_i) {
    free(coord.mu_i);
    coord.mu_i = NULL;
  }
  if (coord.u_i) {
    free(coord.u_i);
    coord.u_i = NULL;
  }
  if (coord.w_i) {
    free(coord.w_i);
    coord.w_i = NULL;
  }
}