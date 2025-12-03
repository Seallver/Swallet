#ifndef NETWORK_H
#define NETWORK_H

#include "../common/crypto_utils.h"
#include "../common/params.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/time.h>

#define BUFFER_SIZE 4096
#define MAX_PARTIES 3

// 网络消息类型
typedef enum {
  ACK,              // ACK
  MSG_PUBLIC_VK,    //参与方公布的公钥分片
  MSG_PRESIGN_DATA, // 协调器发送的预签名数据
  MSG_KEY_EXCHANGE, // 参与方之间的密钥交换
  MSG_UV_DATA,      // 参与方发送的u_i, v_i数据
  REQUEST_SIGN,     // 签名请求
  MSG_PUBLIC_R,     // 公开参数R
  SIGNAL_OFFLINE,   // 离线情况
  // PAKE 材料
  MSG_P2C_DELTA,
  MSG_C2P_L,
  MSG_P2C_M,
  // 签名材料
  MSG_C2P_CT,
  MSG_P2C_SIGMA

} MessageType;

// 网络消息结构
typedef struct {
  int type;       // 消息类型
  int src_id;     // 发送方 ID
  int ack;        // 0: 普通消息, 1: ACK
  char data[256]; // 数据
} NetworkMessage;

extern volatile int listen_thread_exit;

// 消息处理回调函数类型
typedef void (*message_handler_t)(const NetworkMessage *msg);

void set_message_handler(message_handler_t handler);

// 监听线程
void *listen_thread(void *arg);

//发送消息
int send_message(int src_id, const char *ip, int port, MessageType type,
                 const char *data);

//广播消息，用于公开参数
int broadcast(MessageType type, const char *data);

// 序列化/反序列化函数
void serialize_bn(char *buffer, const BIGNUM *bn);

BIGNUM *deserialize_bn(const char *buffer);

void serialize_ec_point(char *buffer, const EC_POINT *point);

EC_POINT *deserialize_ec_point(const char *buffer);

#endif