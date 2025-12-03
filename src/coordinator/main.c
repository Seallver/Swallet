#include "../common/crypto_utils.h"
#include "../common/params.h"
#include "keygen.h"
#include "presign.h"
#include "sign.h"
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <unistd.h>

volatile int listen_thread_exit = 0;

int keygen();
int setup();
int presign();
int sign();
int save_data();

int main() {

  // setup
  printf("setup:\n");

  if (!setup()) {
    printf("setup failed\n");
    return 0;
  }

  load_party_config(CONFIG_FILE, 0);
  printf("\n");

  // keygen
  printf("keygen:\n");

  if (!keygen()) {
    printf("keygen failed\n");
    return 0;
  }

  //等待参与方 keygen 结束
  printf("waiting for parties ...\n\n");
  sleep(4);

  // presign
  printf("presign:\n");

  if (!presign()) {
    printf("presign failed\n");
    return 0;
  }

  //等待参与方 presign 结束
  printf("waiting for parties ...\n\n");
  sleep(5);

  // sign
  printf("sign:\n");

  if (!sign()) {
    printf("sign failed\n");
    return 0;
  }

  // save
  if (!save_data()) {
    printf("save failed\n");
    return 0;
  }

  //清理内存
  cleanup_system_params();
  free_coordinator();

  return 0;
}

int setup() {
  printf("Initializing SilentTS-Lite Coordinator...\n");
  if (!init_system_params()) {
    fprintf(stderr, "Failed to initialize system parameters\n");
    return 0;
  }

  printf("System parameters initialized successfully\n");
  return 1;
}

int keygen() {
  // 设置回调函数
  set_message_handler(keygen_message_handler);

  VK = EC_POINT_new(sys_params.group);

  if (!recv_VK()) {
    printf("receive vk failed\n");
  }

  printf("\n");
  return 1;
}

int presign() {
  if (!send_to_parties()) {
    printf("presign failed\n");
  }

  // 设置回调函数
  set_message_handler(presign_message_handler);

  R = EC_POINT_new(sys_params.group);

  if (!recv_R()) {
    printf("presign failed\n");
  }

  printf("\n");
  return 1;
}

int sign() {
  //分配内存
  if (!init_coordinator()) {
    printf("Initialized coordinator failed\n");
  }

  //开始监听本机端口
  listen_thread_exit = 0;
  pthread_t tid2;
  int *arg = malloc(sizeof(int));
  if (!arg)
    return 0;
  *arg = sys_params.parties[0].port;

  // 重新设置回调函数
  set_message_handler(sign_message_handler);

  if (pthread_create(&tid2, NULL, listen_thread, arg) != 0) {
    perror("pthread_create");
    free(arg);
    return 0;
  }

  if (!step1()) {
    printf("step1 failed\n");
    return 0;
  }

  if (!broadcast_offline()) {
    printf("broadcast offline failed\n");
    return 0;
  }

  while (1) {
    if (received >= online_count) {
      received = 0;
      break;
    }
  }

  if (!step3()) {
    printf("step3 failed\n");
    return 0;
  }

  while (1) {
    if (received >= online_count) {
      received = 0;
      break;
    }
  }

  if (!step5()) {
    printf("step5 failed\n");
    return 0;
  }

  if (!step6()) {
    printf("step6 failed\n");
    return 0;
  }

  while (1) {
    if (received >= online_count) {
      received = 0;
      break;
    }
  }

  if (!step8()) {
    printf("step8 failed\n");
    return 0;
  }

  if (!verify(coord.r, coord.s, VK)) {
    printf("verify failed\n");
    return 0;
  } else {
    printf("r (hex): ");
    BN_print_fp(stdout, coord.r);
    printf("\n");

    printf("s (hex): ");
    BN_print_fp(stdout, coord.s);
    printf("\n\n");
  }

  //停止监听
  listen_thread_exit = 1;
  pthread_join(tid2, NULL);
  return 1;
}

int save_data() {
  // save vk
  EC_GROUP *group = EC_GROUP_dup(sys_params.group);
  EC_POINT *vk = EC_POINT_dup(VK, group);
  const char *filename = "vk.pem";

  if (!group || !vk) {
    fprintf(stderr, "group or vk is NULL\n");
    return 0;
  }

  // 获取曲线名称
  int nid = EC_GROUP_get_curve_name(group);
  const char *curve_name = EC_curve_nid2nist(nid);
  if (!curve_name) {
    curve_name = OBJ_nid2sn(nid);
  }
  if (!curve_name) {
    fprintf(stderr, "Cannot determine curve name\n");
    return 0;
  }

  // 计算公钥点大小
  size_t field_size = EC_GROUP_get_degree(group);
  size_t pub_len = 1 + 2 * ((field_size + 7) / 8); // 未压缩格式: 04 + x + y
  unsigned char *pub = malloc(pub_len);
  if (!pub) {
    fprintf(stderr, "malloc failed\n");
    return 0;
  }

  // 转换EC_POINT为字节
  size_t converted_len = EC_POINT_point2oct(
      group, vk, POINT_CONVERSION_UNCOMPRESSED, pub, pub_len, NULL);
  if (converted_len == 0) {
    fprintf(stderr, "EC_POINT_point2oct failed\n");
    free(pub);
    return 0;
  }

  // 创建EVP_PKEY
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  if (!pctx) {
    fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed\n");
    free(pub);
    return 0;
  }

  if (EVP_PKEY_fromdata_init(pctx) <= 0) {
    fprintf(stderr, "EVP_PKEY_fromdata_init failed: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    EVP_PKEY_CTX_free(pctx);
    free(pub);
    return 0;
  }

  OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(
                             OSSL_PKEY_PARAM_GROUP_NAME, (char *)curve_name, 0),
                         OSSL_PARAM_construct_octet_string(
                             OSSL_PKEY_PARAM_PUB_KEY, pub, converted_len),
                         OSSL_PARAM_construct_end()};

  EVP_PKEY *pkey = NULL;
  if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
    fprintf(stderr, "EVP_PKEY_fromdata failed: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    EVP_PKEY_CTX_free(pctx);
    free(pub);
    return 0;
  }

  // 写入文件
  FILE *fp = fopen(filename, "w");
  if (!fp) {
    perror("fopen");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    free(pub);
    return 0;
  }

  if (!PEM_write_PUBKEY(fp, pkey)) {
    fprintf(stderr, "PEM_write_PUBKEY failed: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    fclose(fp);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    free(pub);
    return 0;
  }

  fclose(fp);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(pctx);
  free(pub);

  // --- Save r||s ---
  filename = "Sig_rs.txt";

  char *hex_r = BN_bn2hex(coord.r);
  char *hex_s = BN_bn2hex(coord.s);

  fp = fopen(filename, "w");
  if (!fp) {
    perror("fopen");
    OPENSSL_free(hex_r);
    OPENSSL_free(hex_s);
    return 0;
  }
  fprintf(fp, "Message: \t%s\n", MESSAGE);
  fprintf(fp, "r||s: \t\t%s%s\n", hex_r, hex_s);

  fclose(fp);
  OPENSSL_free(hex_r);
  OPENSSL_free(hex_s);

  printf("Data saved successfully\n");

  return 1;
}