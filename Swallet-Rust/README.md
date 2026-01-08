# Usage

<small style="color: #666">用法和C语言版本相同</small>

### 编译
在主目录下编译

```bash
make
```

编译完成后得到 coordinator 和 party 两个可执行文件

- 若本地测试，进入执行阶段

- 若在不同主机下测试，修改 parties.config

### 配置文件

parties.config 为参与方IP地址及端口配置文件，配置格式为 
```bash
[party_id] [ip_address] [port]
```
- 默认配置为本地测试（127.0.0.1:800X），可自行更改
- party_id 需从 0 开始连续
- party_id 为 0 代表 coordinator ，其余代表 parties

### 执行
coordinator 可直接执行
```bash
./coordinator
```
party 执行格式为
```bash
./party <party ID> [offline flag]
```
- party ID 需要与配置文件中ID对应
- offline flag 为可选参数，默认为 0，代表所有参与方均在线，可将一个参与方置为 1，代表离线

### 本地测试示例
在线测试，分别执行：
```bash
./coordinator
./party 1
./party 2
./party 3
```
一方离线测试，执行：
```bash
./coordinator
./party 1
./party 2
./party 3 1 #代表离线
```