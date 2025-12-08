# Usage

### 编译
在主目录下编译

```bash
make
```

编译完成后得到 server 和 user 两个可执行文件

- 若本地测试，进入执行阶段

- 若在不同主机下测试，修改 parties.config

### 配置文件

parties.config 为参与方IP地址及端口配置文件，配置格式为 
```bash
[party_id] [ip_address] [port]
```
- 默认配置为本地测试（127.0.0.1:800X），可自行更改
- party_id 为 0 代表 server ，1 代表 user

### 执行
服务器方执行
```bash
./server
```

用户方执行
```bash
./user
```

### 本地测试示例
本地在线测试，分别执行：
```bash
./server
./user
```