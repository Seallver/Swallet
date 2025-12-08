#include "../common/crypto_utils.h"
#include "../common/params.h"
#include "../common/time.h"

#include "keygen.h"
#include "register.h"
#include "sign.h"

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <unistd.h>

volatile int listen_thread_exit = 0;

int keygen();
int register_();
int sign();

int main() {
  if (!init_system_params()) {
    fprintf(stderr, "Failed to initialize system parameters\n");
    return 0;
  }
  load_party_config(CONFIG_FILE, 0);
  printf("\n");

  // keygen
  printf("keygen:\n");

  TIME_START(t1);
  if (!keygen()) {
    printf("keygen failed\n");
    return 0;
  }
  TIME_END(t1, "keygen");
  printf("\n");

  // register
  printf("register:\n");

  TIME_START(t2);
  if (!register_()) {
    printf("register failed\n");
    return 0;
  }
  TIME_END(t2, "register:");
  printf("\n");

  // sign
  printf("sign:\n");

  TIME_START(t3);
  if (!sign()) {
    printf("sign failed\n");
    return 0;
  }
  TIME_END(t3, "sign:");
  printf("\n");

  //清理内存
  cleanup_system_params();
  free_key_pair();
  free_register_pair();
  free_sign_data();
  return 0;
}

int keygen() {
  // 设置回调函数
  set_message_handler(keygen_message_handler);
  if (!recv_sk_pk()) {
    printf("receive sk_s、pk failed\n");
  }

  return 1;
}

int register_() {
  if (!generate_register_pair()) {
    fprintf(stderr, "Failed to generate register pair\n");
    return 0;
  }

  return 1;
};

int sign() {

  if (!init_sign_data()) {
    return 0;
  }

  //开始监听本机端口
  listen_thread_exit = 0;
  pthread_t tid;
  int *arg = malloc(sizeof(int));
  if (!arg)
    return 0;
  *arg = sys_params.parties[0].port;

  // 重新设置回调函数
  set_message_handler(sign_message_handler);

  if (pthread_create(&tid, NULL, listen_thread, arg) != 0) {
    perror("pthread_create");
    free(arg);
    return 0;
  }

  if (!commit()) {
    return 0;
  }

  while (1) {
    if (received) {
      received = 0;
      break;
    }
  }

  if (!server_sign()) {
    return 0;
  }

  //停止监听
  listen_thread_exit = 1;
  pthread_join(tid, NULL);

  return 1;
}
