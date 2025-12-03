#ifndef COOR_PRESIGN_H
#define COOR_PRESIGN_H

#include "../common/crypto_utils.h"
#include "../common/network.h"
#include "../common/params.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

int send_to_parties();

//回调函数
void presign_message_handler(const NetworkMessage *msg);

int recv_R();

extern EC_POINT *R;
extern int R_received_count;

#endif