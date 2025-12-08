#include "network.h"
#include "../common/crypto_utils.h"
#include "../common/params.h"
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <sys/time.h>

const char *message_type_to_str(int type) {
  switch (type) {
  case ACK:
    return "ACK";
  case DATA_SK_PK:
    return "DATA_SK_PK";
  case DATA_ELGAMAL_PARAMS:
    return "DATA_ELGAMAL_PARAMS";
  case DATA_R:
    return "DATA_R";
  case DATA_C_CT:
    return "DATA_C_CT";
  case DATA_S:
    return "DATA_S";
  default:
    return "UNKNOWN";
  }
}

// 序列化 BIGNUM 到二进制
void serialize_bn(char *buffer, const BIGNUM *bn) {
  if (!bn) {
    memset(buffer, 0, 32);
    return;
  }

  int bn_size = BN_num_bytes(bn);
  if (bn_size > 32) {
    bn_size = 32;
  }

  memset(buffer, 0, 32);

  BN_bn2bin(bn, (unsigned char *)buffer + (32 - bn_size));
}

// 从二进制反序列化 BIGNUM
BIGNUM *deserialize_bn(const char *buffer) {
  if (!buffer) {
    return NULL;
  }

  BIGNUM *bn = BN_new();
  if (!bn) {
    return NULL;
  }

  BN_bin2bn((const unsigned char *)buffer, 32, bn);
  return bn;
}

// 序列化 EC_POINT 到字符串
void serialize_ec_point(char *buffer, const EC_POINT *point) {
  if (!point || !sys_params.group) {
    memset(buffer, 0, 128);
    return;
  }

  char *hex_str = EC_POINT_point2hex(sys_params.group, point,
                                     POINT_CONVERSION_COMPRESSED, NULL);
  if (hex_str) {
    strncpy(buffer, hex_str, 127);
    buffer[127] = '\0';
    OPENSSL_free(hex_str);
  } else {
    memset(buffer, 0, 128);
  }
}

// 从字符串反序列化 EC_POINT
EC_POINT *deserialize_ec_point(const char *buffer) {
  if (!buffer || !sys_params.group || strlen(buffer) == 0) {
    return NULL;
  }

  EC_POINT *point = EC_POINT_new(sys_params.group);
  if (EC_POINT_hex2point(sys_params.group, buffer, point, NULL)) {
    return point;
  } else {
    EC_POINT_free(point);
    return NULL;
  }
}

// 发送消息函数
int send_message(int src_id, const char *ip, int port, MessageType type,
                 const char *data) {
  int max_retry = 10;
  for (int retry = 0; retry < max_retry; retry++) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
      perror("socket");
      return 0;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
      perror("inet_pton");
      close(sock);
      return 0;
    }

    struct timeval timeout = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      close(sock);
      sleep(1);
      continue;
    }

    NetworkMessage msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = type;
    msg.src_id = src_id;
    msg.ack = 0;
    if (data)
      memcpy(msg.data, data, sizeof(msg.data));

    if (send(sock, &msg, sizeof(msg), 0) < 0) {
      perror("send");
      close(sock);
      sleep(1);
      continue;
    }

    // 等待 ACK
    NetworkMessage ack_msg;
    int n = recv(sock, &ack_msg, sizeof(ack_msg), 0);
    if (n > 0 && ack_msg.ack == 1) {
      printf("[+] Sent message and received ACK from party %s:%d \t MESSAGE "
             "TYPE: %s \n",
             ip, port, message_type_to_str(type));
      close(sock);
      return 1;
    } else {
      printf("Retry sending message...\n");
    }

    close(sock);
    sleep(1);
  }

  printf("[+] Failed to send message after retries\n");
  return 0;
}

// 消息处理回调函数类型
typedef void (*message_handler_t)(const NetworkMessage *msg);

// 全局消息处理器
static message_handler_t message_handler = NULL;

// 设置消息处理器
void set_message_handler(message_handler_t handler) {
  message_handler = handler;
}

// 监听线程
void *listen_thread(void *arg) {
  int port = *(int *)arg;

  int server_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (server_sock < 0) {
    perror("socket");
    return NULL;
  }

  int opt = 1;
  setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    close(server_sock);
    return NULL;
  }

  if (listen(server_sock, 10) < 0) {
    perror("listen");
    close(server_sock);
    return NULL;
  }

  printf("[*] listening on port %d...\n", port);

  struct timeval timeout;
  timeout.tv_sec = 3; // 等待 3 秒
  timeout.tv_usec = 0;
  setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  while (!listen_thread_exit) {

    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);

    int client_sock =
        accept(server_sock, (struct sockaddr *)&client_addr, &len);

    if (client_sock < 0) {
      usleep(10000);
      continue;
    }

    /* 设置接收超时 */
    struct timeval timeout2;
    timeout2.tv_sec = 10;
    timeout2.tv_usec = 0;
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout2,
               sizeof(timeout2));

    NetworkMessage msg;
    int n = recv(client_sock, &msg, sizeof(NetworkMessage), 0);

    if (n == sizeof(NetworkMessage)) {
      printf("[+] Received message from party %d \t\t\t\t MESSAGE TYPE: %s\n",
             msg.src_id, message_type_to_str(msg.type));
    }

    /* 发送 ACK */
    if (msg.ack == 0) {
      NetworkMessage ack_msg;
      memset(&ack_msg, 0, sizeof(ack_msg));
      ack_msg.type = ACK;
      ack_msg.src_id = sys_params.current_party_id;
      ack_msg.ack = 1;
      send(client_sock, &ack_msg, sizeof(ack_msg), 0);
    }

    if (message_handler)
      message_handler(&msg);

    close(client_sock);
  }

  close(server_sock);
  return NULL;
}