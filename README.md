# SFTP文件同步工具

一个高效、可靠的SFTP文件同步工具，支持多服务器、多目录同步，具备断点续传、MD5校验等功能。

## 特性

- **多服务器支持**：可同时配置多个SFTP服务器
- **多目录同步**：支持每个服务器配置多个备份任务
- **递归下载**：可选择递归下载整个目录树或仅当前目录
- **MD5校验**：可选的文件完整性校验
- **临时目录**：支持独立的临时文件存储目录
- **并发下载**：支持多线程批量下载
- **断点续传**：支持失败重试和断点续传
- **时间戳保持**：可选择保持文件的时间戳

## 安装

### 环境要求

- Python 3.7+
- paramiko
- cryptography

### 安装依赖

```bash
pip install -r requirements.txt
```

或者手动安装：

```bash
pip install paramiko cryptography
```

## 配置文件详解

配置文件使用JSON格式，路径默认为`sftp_config.json`。

### 全局配置项

```json
{
  "setting": {
    "temp_dir": "./temp",
    "log_dir": "./logs",
    "batch_delay": 30,
    "max_retries": 3,
    "max_threads": 10,
    "retry_delay": 30,
    "preserve_timestamps": true
  },
  "servers": {
    // 服务器配置...
  }
}
```

#### 全局配置项说明

| 配置项 | 类型 | 默认值 | 说明 | 填写方式 |
|--------|------|--------|------|----------|
| `setting.temp_dir` | 字符串 | 无 | 临时文件存储目录，下载时的临时文件会先保存到这里 | 填写绝对路径或相对路径，如 `"./temp"` 或 `"/path/to/temp"` |
| `setting.log_dir` | 字符串 | 无 | 日志文件存储目录 | 填写绝对路径或相对路径，如 `"./logs"` |
| `setting.batch_delay` | 整数 | 30 | 批次间延迟时间（秒） | 填写数字，如 `30` |
| `setting.max_retries` | 整数 | 3 | 单个文件下载失败最大重试次数 | 填写数字，如 `5` |
| `setting.max_threads` | 整数 | 5 | 并发下载线程数 | 填写数字，如 `10` |
| `setting.retry_delay` | 整数 | 30 | 重试间隔时间（秒） | 填写数字，如 `60` |
| `setting.preserve_timestamps` | 布尔 | true | 是否保持文件时间戳 | 填写 `true` 或 `false` |

### 服务器配置项

每个服务器的配置如下：

```json
{
  "servers": {
    "server_name": {
      "host": "sftp.example.com",
      "port": 22,
      "username": "username",
      "password": "encrypted_password",
      "backup_settings": [
        {
          "remote_dir": "/remote/path/",
          "backup_dir": "/local/backup/path/",
          "pattern": ".*\\.txt$",
          "recursive": true,
          "check_by_md5": false,
          "batch_size": 1000
        }
      ]
    }
  }
}
```

#### 服务器配置项说明

| 配置项 | 类型 | 必填 | 说明 | 填写方式 |
|--------|------|------|------|----------|
| `host` | 字符串 | 是 | SFTP服务器地址 | 填写IP地址或域名，如 `"192.168.1.100"` 或 `"sftp.example.com"` |
| `port` | 整数 | 是 | SFTP服务器端口 | 填写端口号，通常是 `22` |
| `username` | 字符串 | 是 | 登录用户名 | 填写用户名字符串，如 `"sftp_user"` |
| `password` | 字符串 | 是 | 加密后的登录密码 | 使用RSA加密后的密码，不能填写明文密码 |
| `backup_settings` | 数组 | 是 | 备份设置数组，可配置多个备份任务 | 包含多个备份任务对象的数组 |

#### 备份设置配置项说明

| 配置项 | 类型 | 必填 | 说明         | 填写方式                                                                                    |
|--------|------|------|------------|-----------------------------------------------------------------------------------------|
| `remote_dir` | 字符串 | 是 | 远程目录路径     | 填写远程服务器上的目录路径，如 `"/upload/data/"`                                                       |
| `backup_dir` | 字符串 | 是 | 本地备份目录路径   | 填写本地存储路径，如 `"./backup/"`                                                                |
| `pattern` | 字符串 | 否 | 正则表达式匹配文件名或相对路径 | 当 `recursive=false` 时匹配文件名，当 `recursive=true` 时匹配相对于remote_dir的路径；如 `".*\\.txt$"`、`"subdir/.*\\.csv$"`、`".*"（全部文件） |
| `recursive` | 布尔 | 否 | 是否递归下载子目录  | `true` 递归下载，`false` 仅当前目录，默认 `false`                                                    |
| `check_by_md5` | 布尔 | 否 | 下载前是否进行MD5校验  | `true` 进行校验（下载前检查本地文件是否已存在且完整），`false` 不校验，默认 `false`；此配置项在每个备份任务中单独设置，以实现精确控制 |
| `batch_size` | 整数 | 否 | 每批处理的文件数量 | 填写数字，如 `1000`，默认值为 `1000` |

### 配置文件示例

```json
{
  "setting": {
    "temp_dir": "./temp",
    "log_dir": "./logs",
    "batch_delay": 30,
    "max_retries": 3,
    "max_threads": 10,
    "retry_delay": 30,
    "preserve_timestamps": true
  },
  "servers": {
    "production_server": {
      "host": "sftp.example.com",
      "port": 22,
      "username": "prod_user",
      "password": "ENCRYPTED_PASSWORD_HERE",
      "backup_settings": [
        {
          "remote_dir": "/data/logs/${datetime.now() - timedelta(days=1)}",
          "backup_dir": "./logs_yesterday",
          "pattern": ".*\\.log$",
          "recursive": false,
          "check_by_md5": true,
          "batch_size": 1000
        },
        {
          "remote_dir": "/data/reports/",
          "backup_dir": "./reports",
          "pattern": "report_.*\\.pdf$",
          "recursive": true,
          "check_by_md5": false,
          "batch_size": 1000
        }
      ]
    }
  }
}
```

### 配置项填写说明

#### 1. 服务器配置填写说明

- `host`: 可以是IP地址（如 "192.168.1.100"）或域名（如 "sftp.example.com"）
- `port`: 通常为 22，除非服务器特别配置了其他端口
- `username`: SFTP服务器的登录用户名
- `password`: 必须使用RSA加密后的密码，不能使用明文密码

#### 2. 路径配置填写说明

- `remote_dir`: 远程服务器上的目录路径，支持表达式，如 `${datetime.now() - timedelta(days=1)}` 用于动态生成日期路径
- `backup_dir`: 本地备份目录路径，建议使用相对路径或绝对路径
- `setting.temp_dir`: 临时文件存储目录，下载的临时文件会先保存到这里，下载完成后移动到备份目录

#### 3. 文件匹配填写说明

- `pattern`: 使用正则表达式匹配文件名或相对路径（取决于recursive参数）
  - 当 `recursive=false` 时，匹配文件名（如 `.*\\.txt$` 匹配所有txt文件）
  - 当 `recursive=true` 时，匹配相对于remote_dir的路径（如 `subdir/.*\\.txt$` 匹配subdir下的所有txt文件）

#### 4. 递归下载说明

- `recursive: true`: 会下载远程目录及其所有子目录中的文件，保持目录结构
- `recursive: false`: 只下载远程目录中的文件，不包括子目录

#### 5. MD5校验说明

- `check_by_md5: true`: 下载前会进行MD5校验，检查本地文件是否已存在且完整，如果完整则跳过下载，避免重复下载
- `check_by_md5: false`: 不进行MD5校验，直接下载文件
- 注意：此配置项在每个备份任务中单独设置，以实现对不同备份任务的精确控制

## 密码加密

密码需要使用RSA加密，不能使用明文密码。请使用提供的加密工具或按照以下步骤加密：

1. 生成RSA密钥对
2. 使用公钥加密密码
3. 将加密后的密码填入配置文件

## 使用方法

### 基本用法

```bash
python main.py --server server_name
```

### 多服务器同步

```bash
python main.py --server server1,server2,server3
```

### 指定配置文件

```bash
python main.py --server server_name --config /path/to/config.json
```

### 示例

```bash
# 同步单个服务器
python main.py --server test_server

# 同步多个服务器
python main.py --server test_server,production_server

# 指定配置文件同步
python main.py --server test_server --config ./custom_config.json
```

## 工作流程

1. **初始化**：读取配置文件，建立SFTP连接池
2. **文件扫描**：扫描远程目录中的文件
3. **下载准备**：创建本地目录，准备临时文件
4. **文件下载**：多线程下载文件到临时目录
5. **文件移动**：下载完成后移动到备份目录
6. **校验清理**：可选的MD5校验，清理临时文件
7. **重复处理**：处理下一个备份任务

## 临时文件处理

- 下载的文件会先保存到 `temp_dir` 指定的目录
- 临时文件名使用 `.tmp` 扩展名
- 下载完成后，临时文件会被移动到正确的备份目录
- 程序启动和结束时会自动清理临时文件

## 日志记录

- 日志文件保存在 `log_dir` 指定的目录
- 每次运行会创建一个新的日志文件
- 日志包含详细的同步过程信息

## 注意事项

1. **安全性**：密码必须加密，不能使用明文
2. **权限**：确保对备份目录有写入权限
3. **网络**：确保能正常连接到SFTP服务器
4. **磁盘空间**：确保有足够的磁盘空间存储备份文件和临时文件
5. **并发控制**：合理设置 `max_threads` 以避免服务器负载过高

## 常见问题

### Q: 如何生成加密密码？
A: 使用项目中的 `rsa_encrypt.py` 工具或使用RSA加密算法加密明文密码。

### Q: 如何动态设置路径？
A: 使用 `${expression}` 语法，如 `${datetime.now() - timedelta(days=1)}` 来生成昨天的日期。支持datetime和timedelta对象。

### Q: 如何只同步特定文件？
A: 使用 `pattern` 配置项指定正则表达式模式，如 `".*\\.txt$"` 只同步文本文件。

### Q: 下载失败怎么办？
A: 程序会自动重试，重试次数由 `max_retries` 配置项控制。

### Q: 如何控制MD5校验？
A: 在每个备份设置中单独配置 `check_by_md5` 参数，可以为不同的备份任务设置不同的校验策略。当设置为 `true` 时，下载前会检查本地文件是否已存在且完整，如果完整则跳过下载，避免重复下载。