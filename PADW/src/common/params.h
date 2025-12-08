#ifndef PARAMS_H
#define PARAMS_H

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <unistd.h>

#define HASH_LEN 32                  // SHA-256 输出字节
#define NUM_PARTIES 1                // 参与方数目
#define CONFIG_FILE "parties.config" // 网络配置文件名

#define PASSWORD "password"       // 注册口令
#define PASSWORD_PRIME "password" // 登录口令

#define MESSAGE "hello world"  //消息
#define DERIVATION_ID "tx_123" //密钥派生ID

#define LAMBDA 128 //安全参数

// 参与方网络地址
typedef struct {
  char ip[16];
  int port;
} PartyAddress;

// 系统参数结构体
typedef struct {
  EC_GROUP *group;     // 椭圆曲线群
  EC_POINT *g;         // 生成元
  BIGNUM *q;           // 群的阶
  const EVP_MD *H_sig; // ECDSA 签名哈希函数

  char *derivation_ID; //密钥派生ID

  // 网络配置
  PartyAddress parties[NUM_PARTIES + 1];
  int current_party_id;
} system_params_t;

// 全局系统参数
extern system_params_t sys_params;

// 初始化系统参数
int init_system_params();

// 清理系统参数
void cleanup_system_params();

// 网络配置管理函数
int load_party_config(const char *config_file, int party_id);
int create_default_config(const char *config_file);
void print_network_config();

void print_bn(const char *name, const BIGNUM *bn);

#endif