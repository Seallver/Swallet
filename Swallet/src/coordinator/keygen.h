#ifndef COOR_KEYGEN_H
#define COOR_KEYGEN_H

#include "../common/crypto_utils.h"
#include "../common/network.h"
#include "../common/params.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

// coordinator在keygen阶段只负责接收参与方公开的vk_i并聚合出vk

//回调函数
void keygen_message_handler(const NetworkMessage *msg);

int recv_VK();

extern EC_POINT *VK;
extern int VK_received_count;

#endif