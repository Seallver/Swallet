#include "params.h"
#include <openssl/err.h>

system_params_t sys_params;

int init_system_params() {
  OpenSSL_add_all_algorithms();

  // 创建 secp256k1 曲线
  sys_params.group = EC_GROUP_new_by_curve_name(NID_secp256k1);
  if (!sys_params.group) {
    return 0;
  }

  // 获取生成元 g
  sys_params.g = EC_POINT_new(sys_params.group);
  const EC_POINT *generator = EC_GROUP_get0_generator(sys_params.group);
  if (!EC_POINT_copy(sys_params.g, generator)) {
    return 0;
  }

  // 获取阶 q
  sys_params.q = BN_new();
  if (!EC_GROUP_get_order(sys_params.group, sys_params.q, NULL)) {
    return 0;
  }

  // 设置哈希函数为 SHA-256
  sys_params.H_sig = EVP_sha256();

  return 1;
}

void cleanup_system_params() {
  if (sys_params.group)
    EC_GROUP_free(sys_params.group);
  if (sys_params.g)
    EC_POINT_free(sys_params.g);
  if (sys_params.q)
    BN_free(sys_params.q);
}
