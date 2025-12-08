#include "../common/crypto_utils.h"
#include "../common/network.h"
#include "../common/params.h"
#include "../common/time.h"
#include "keyDerivation.h"
#include "keygen.h"
#include "register.h"
#include "sign.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <sys/types.h>

volatile int listen_thread_exit = 0;

int keygen();
int register_();
int key_derivation();
int sign();

int party_id = 1;
int listen_port;

int main() {
  if (!init_system_params()) {
    fprintf(stderr, "Failed to initialize system parameters\n");
    return 0;
  }
  load_party_config(CONFIG_FILE, party_id);
  listen_port = sys_params.parties[sys_params.current_party_id].port;
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
  TIME_END(t2, "register");
  printf("\n");

  // key derivation
  printf("key derivation:\n");
  TIME_START(t3);
  if (!key_derivation()) {
    printf("key derivation failed\n");
    return 0;
  } else {
    printf("key derivation successfully\n");
  }
  TIME_END(t3, "key derivation");
  printf("\n");

  // sign
  printf("sign:\n");
  TIME_START(t4);
  if (!sign()) {
    printf("sign failed\n");
    return 0;
  }
  TIME_END(t4, "sign");
  printf("\n");

  printf("verify:\n");
  TIME_START(t5);
  if (!verify()) {
    return 0;
  } else {
    printf("Signature verification SUCCESS\n");
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    if (EC_POINT_get_affine_coordinates(sys_params.group, key_pair.pk, x, y,
                                        NULL)) {
      char *x_hex = BN_bn2hex(x);
      char *y_hex = BN_bn2hex(y);

      printf("PK :\n");
      printf("  x = %s\n", x_hex);
      printf("  y = %s\n", y_hex);

      OPENSSL_free(x_hex);
      OPENSSL_free(y_hex);
    }

    if (EC_POINT_get_affine_coordinates(sys_params.group, sign_data.R_prime, x,
                                        y, NULL)) {
      char *x_hex = BN_bn2hex(x);
      char *y_hex = BN_bn2hex(y);

      printf("R :\n");
      printf("  x = %s\n", x_hex);
      printf("  y = %s\n", y_hex);

      OPENSSL_free(x_hex);
      OPENSSL_free(y_hex);
    }

    BN_free(x);
    BN_free(y);

    printf("s: ");
    BN_print_fp(stdout, sign_data.s_prime);
  }
  TIME_END(t5, "verify");

  cleanup_system_params();
  free_key_pair();
  free_register_pair();
  free_sign_data();
  return 0;
}

int keygen() {
  if (!generate_key_pair(&key_pair)) {
    fprintf(stderr, "Failed to generate key pair\n");
    cleanup_system_params();
    return 0;
  }
  return 1;
}

int register_() {
  // 设置回调函数
  set_message_handler(register_message_handler);
  if (!recv_elgamal_params()) {
    printf("receive sk_s、pk failed\n");
  }

  return 1;
};

int key_derivation() {
  if (!RandSK()) {
    fprintf(stderr, "Failed to derivate sk\n");
    return 0;
  }
  if (!RandPK()) {
    fprintf(stderr, "Failed to derivate pk\n");
    return 0;
  }
  return 1;
}

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
  *arg = sys_params.parties[1].port;

  // 重新设置回调函数
  set_message_handler(sign_message_handler);

  if (pthread_create(&tid, NULL, listen_thread, arg) != 0) {
    perror("pthread_create");
    free(arg);
    return 0;
  }

  while (1) {
    if (received) {
      received = 0;
      break;
    }
  }

  if (!gen_challenge()) {
    return 0;
  }

  while (1) {
    if (received) {
      received = 0;
      break;
    }
  }

  if (!user_sign()) {
    return 0;
  }

  //停止监听
  listen_thread_exit = 1;
  pthread_join(tid, NULL);

  return 1;
}