#include "../common/crypto_utils.h"
#include "../common/network.h"
#include "../common/params.h"
#include "../common/time.h"
#include "keygen.h"
#include "presign.h"
#include "sign.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <stdio.h>

volatile int listen_thread_exit = 0;

int setup();
int keygen();
int presign();
int sign();

int party_id;
int listen_port;

int main(int argc, char *argv[]) {

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <party ID> [offline flag]\n", argv[0]);
    return 1;
  }

  party_id = atoi(argv[1]);

  int offline_flag = 0;
  if (argc >= 3) {
    offline_flag = atoi(argv[2]);
  }

  // 验证参数
  if (offline_flag != 0 && offline_flag != 1) {
    fprintf(stderr, "Error: offline_flag must be 0 or 1\n");
    return 1;
  }

  // setup
  printf("setup:\n");
  TIME_START(t1);
  if (!setup()) {
    printf("setup failed\n");
    return 0;
  }
  TIME_END(t1, "setup");

  load_party_config(CONFIG_FILE, party_id);
  listen_port = sys_params.parties[sys_params.current_party_id].port;
  printf("\n");

  // keygen
  printf("keygen:\n");
  TIME_START(t2);
  if (!keygen()) {
    printf("keygen failed\n");
    return 0;
  }
  TIME_END(t2, "keygen");
  printf("\n");

  //等待其他参与方 presign 结束
  printf("waiting for parties ...\n\n");
  sleep(3);

  // presign
  printf("presign:\n");
  TIME_START(t3);
  if (!presign()) {
    printf("presign failed\n");
    return 0;
  }
  TIME_END(t3, "presign");
  printf("\n");

  // 如果是离线参与方直接放弃签名阶段
  if (offline_flag) {
    printf("offline now\n");
    free_key_pair();
    free_presigndata();
    free_recvdata();
    cleanup_system_params();
    return 0;
  }

  //等待其他参与方 presign 结束
  printf("waiting for parties ...\n\n");
  sleep(3);

  // sign
  printf("sign:\n");
  TIME_START(t4);
  if (!sign()) {
    printf("sign failed\n");
    return 0;
  }
  TIME_END(t4, "sign");

  free_key_pair();
  free_presigndata();
  free_recvdata();
  free_party();
  cleanup_system_params();
  return 0;
}

int setup() {
  printf("Initializing SilentTS-Lite Party...\n");
  if (!init_system_params()) {
    fprintf(stderr, "Failed to initialize system parameters\n");
    return 0;
  }

  printf("System parameters initialized successfully\n");
  return 1;
}

int keygen() {
  if (!generate_key_pair(&key_pair)) {
    fprintf(stderr, "Failed to generate key pair\n");
    cleanup_system_params();
    return 0;
  }

  char *priv_hex = BN_bn2hex(key_pair.secret_share);
  char *pub_hex = EC_POINT_point2hex(sys_params.group, key_pair.public_share,
                                     POINT_CONVERSION_COMPRESSED, NULL);

  printf("Key pair generated successfully:\n");
  printf("  Secret share x_i: %s\n", priv_hex);
  printf("  Public share y_i: %s\n", pub_hex);

  // 创建监听线程
  listen_thread_exit = 0;
  pthread_t tid;
  int *arg = malloc(sizeof(int));
  if (!arg)
    return 0;
  *arg = listen_port;

  // 设置回调函数
  set_message_handler(keygen_message_handler);

  if (pthread_create(&tid, NULL, listen_thread, arg) != 0) {
    perror("pthread_create");
    free(arg);
    return 0;
  }

  if (!public_VK()) {
    perror("public_message");
    return 0;
  }

  //等待接收所有参与方公开的VK
  while (1) {
    if (vk_received_count >= NUM_PARTIES - 1) {
      break;
    }
  }

  //停止监听
  listen_thread_exit = 1;
  pthread_join(tid, NULL);

  OPENSSL_free(priv_hex);
  OPENSSL_free(pub_hex);
  return 1;
}

int presign() {
  //初始化结构体
  if (!init_presign()) {
    printf("Initialized presign structure failed\n");
  }

  presign_data.x = BN_dup(key_pair.secret_share);

  // 创建监听线程
  listen_thread_exit = 0;
  pthread_t tid;
  int *arg = malloc(sizeof(int));
  if (!arg)
    return 0;
  *arg = listen_port;

  // 设置回调函数
  set_message_handler(presign_message_handler);

  if (pthread_create(&tid, NULL, listen_thread, arg) != 0) {
    perror("pthread_create");
    free(arg);
    return 0;
  }

  //等待接收coordinator发送的数据
  while (1) {
    if (recv_data.received) {
      recv_data.received = 0;
      break;
    }
  }

  if (!compute_u_v(&presign_data)) {
    fprintf(stderr, "Failed to compute u_i and v_i\n");
  }

  if (!exchange_u_v(&presign_data)) {
    perror("send_message");
    return 0;
  } else {
    char *pre_u_hex = BN_bn2hex(presign_data.pre_u);
    char *pre_v_hex = BN_bn2hex(presign_data.pre_v);
    char *u_hex = BN_bn2hex(presign_data.u);
    char *v_hex = BN_bn2hex(presign_data.v);
    printf(
        "[+] Pre-signature materials computed successfully:\n    u_i: %s\n    "
        "v_i: "
        "%s\n    u_i-1: %s\n    v_i-1: %s\n",
        u_hex, v_hex, pre_u_hex, pre_v_hex);
    OPENSSL_free(u_hex);
    OPENSSL_free(v_hex);
    OPENSSL_free(pre_u_hex);
    OPENSSL_free(pre_v_hex);
  }

  if (!public_R()) {
    perror("public_message");
    return 0;
  }

  //等待接收所有参与方公开的R
  while (1) {
    if (recv_data.R_received >= NUM_PARTIES - 1) {
      break;
    }
  }

  if (!get_point_x_coordinate(presign_data.sum_R, presign_data.r)) {
    perror("compute r");
    return 0;
  }

  //停止监听
  listen_thread_exit = 1;
  pthread_join(tid, NULL);

  return 1;
}

int sign() {
  //初始化结构体
  if (!init_party()) {
    printf("Initialized party failed\n");
  }

  //开始监听本机端口
  listen_thread_exit = 0;
  pthread_t tid;
  int *arg = malloc(sizeof(int));
  if (!arg)
    return 0;
  *arg = listen_port;

  // 重新设置回调函数
  set_message_handler(sign_message_handler);

  if (pthread_create(&tid, NULL, listen_thread, arg) != 0) {
    perror("pthread_create");
    free(arg);
    return 0;
  }

  //等待接收签名请求
  while (1) {
    if (sign_flag) {
      sign_flag = 0;
      break;
    }
  }

  //等待接收离线id信息
  while (1) {
    if (sign_flag) {
      sign_flag = 0;
      break;
    }
  }

  if (!step2()) {
    printf("step2 failed\n");
    return 0;
  }

  while (1) {
    if (received) {
      received = 0;
      break;
    }
  }

  if (!step4()) {
    printf("step4 failed\n");
    return 0;
  }

  while (1) {
    if (received) {
      received = 0;
      break;
    }
  }

  if (!step7()) {
    printf("step7 failed\n");
    return 0;
  }

  //停止监听
  listen_thread_exit = 1;
  pthread_join(tid, NULL);
  return 1;
}