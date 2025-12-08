#include "params.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int load_party_config(const char *config_file, int party_id) {
  // 如果文件不存在，创建默认配置
  if (access(config_file, F_OK) != 0) {
    printf("Config file not found, creating default: %s\n", config_file);
    if (!create_default_config(config_file)) {
      return 0;
    }
  }

  FILE *file = fopen(config_file, "r");
  if (!file) {
    fprintf(stderr, "Cannot open config file: %s\n", config_file);
    return 0;
  }

  char line[256];
  int parties_loaded = 0;

  while (fgets(line, sizeof(line), file)) {
    // 跳过注释和空行
    if (line[0] == '#' || line[0] == '\n')
      continue;

    int id;
    char ip[16];
    int port;

    if (sscanf(line, "%d %15s %d", &id, ip, &port) == 3) {
      if (id >= 0 && id <= NUM_PARTIES) {
        strcpy(sys_params.parties[id].ip, ip);
        sys_params.parties[id].port = port;
        parties_loaded++;
      }
    }
  }

  fclose(file);

  if (parties_loaded != NUM_PARTIES + 1) {
    fprintf(stderr, "Incomplete configuration: loaded %d/%d parties\n",
            parties_loaded, NUM_PARTIES + 1);
    return 0;
  }

  sys_params.current_party_id = party_id;

  printf("Loaded configuration for %d parties\n", NUM_PARTIES + 1);
  print_network_config();

  return 1;
}

int create_default_config(const char *config_file) {
  FILE *file = fopen(config_file, "w");
  if (!file) {
    fprintf(stderr, "Cannot create config file: %s\n", config_file);
    return 0;
  }

  fprintf(file, "# SilentTS-Lite Parties Configuration\n");
  fprintf(file, "# Format: [party_id] [ip_address] [port]\n");
  fprintf(file, "# For local testing, use 127.0.0.1 with different ports\n\n");

  for (int i = 0; i <= NUM_PARTIES; i++) {
    fprintf(file, "%d 127.0.0.1 %d\n", i, 8000 + i);
  }

  fclose(file);
  printf("Created default configuration: %s\n", config_file);
  return 1;
}

void print_network_config() {
  printf("Network configuration:\n");
  for (int i = 0; i <= NUM_PARTIES; i++) {
    printf("  Party %d: %s:%d", i, sys_params.parties[i].ip,
           sys_params.parties[i].port);
    if (i == sys_params.current_party_id) {
      printf(" (this node)");
    }
    printf("\n");
  }
}