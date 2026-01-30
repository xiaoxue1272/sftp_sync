#!/usr/bin/env python3
"""
SFTP文件同步脚本 (简化版) - 支持连接池
"""
import hashlib
import os
import shutil
import sys
import time
import logging
import argparse
import base64
import re
import queue
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import paramiko
import json

# 全局配置
CONFIG_FILE = "sftp_config.json"
TEMP_EXTENSION = ".tmp"  # 临时文件扩展名
DEFAULT_TEMP_DIR_SUFFIX = ".tmp_downloading"  # 默认临时目录后缀

# 日志格式化器
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[31;1m',
    }

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}\033[0m"
        return super().format(record)


logger = logging.getLogger('SFTP_SYNC')


class ExpressionProcessor:
    """表达式处理器 - 支持简单的Python表达式"""

    @staticmethod
    def evaluate_expression(expr: str) -> Any:
        """执行表达式并返回结果"""
        if not expr or not expr.strip():
            return expr

        # 检查是否是 ${...} 格式
        match = re.match(r'^\$\{([^}]+)}$', expr.strip())
        if not match:
            return expr  # 不是表达式，直接返回原值

        expr_content = match.group(1)

        try:
            # 使用更安全的方式执行表达式，限制可用的命名空间
            allowed_names = {
                "__builtins__": {},
                "datetime": datetime,
                "timedelta": timedelta,
            }
            result = eval(expr_content, allowed_names)
            return result
        except Exception as e:
            logger.warning(f"表达式执行失败: {expr} - {e}")
            return expr  # 执行失败，返回原表达式

    @staticmethod
    def evaluate_to_string(expr: str) -> str:
        """执行表达式并返回字符串结果"""
        result = ExpressionProcessor.evaluate_expression(expr)

        # 如果结果是datetime对象，转换为字符串
        if isinstance(result, datetime):
            return result.strftime('%Y%m%d')  # 默认格式
        elif isinstance(result, timedelta):
            return str(result.days)
        else:
            return str(result)

    @staticmethod
    def process_path(path_str: str) -> str:
        """处理路径中的日期表达式 ${datetime.now() - timedelta(days=1)}"""
        if not path_str:
            return path_str

        result = path_str

        # 查找所有 ${...} 表达式
        pattern = re.compile(r'\$\{([^}]+)}')

        for match in pattern.finditer(path_str):
            expr = match.group(1)
            full_expr = match.group(0)  # 完整的 ${...} 表达式

            try:
                # 执行表达式
                result_value = ExpressionProcessor.evaluate_to_string(full_expr)

                # 替换原表达式
                result = result.replace(full_expr, result_value)

            except Exception as e:
                logger.warning(f"表达式执行失败，保持原样: {expr} - {e}")
                # 保持原样

        return result


class PasswordDecryptor:
    """RSA密码解密器"""

    def __init__(self, key_file: str = ".encrypt_private.pem"):
        self.key_file = key_file
        self.private_key = self._load_key()

    def _load_key(self):
        """加载RSA私钥"""
        if not os.path.exists(self.key_file):
            logger.error(f"私钥文件 {self.key_file} 不存在")
            sys.exit(1)

        try:
            with open(self.key_file, 'rb') as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            logger.error(f"加载私钥失败: {e}")
            raise

    def decrypt(self, encrypted_text: str) -> str:
        """解密文本"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_text.encode())
            decrypted = self.private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode()
        except Exception as e:
            logger.error(f"密码解密失败: {e}")
            raise ValueError("密码解密失败")


class SFTPConnection:
    """SFTP连接封装类"""

    def __init__(self, host: str, port: int, username: str, password: str):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssh_client = None
        self.sftp_client = None
        self.last_used = time.time()
        self.in_use = False
        self.lock = threading.Lock()

    def connect(self) -> bool:
        """连接到SFTP服务器"""
        try:
            with self.lock:
                if self.ssh_client is not None and self.ssh_client.get_transport() and self.ssh_client.get_transport().is_active():
                    return True

                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.ssh_client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=30,
                    allow_agent=False,
                    look_for_keys=False
                )
                self.sftp_client = self.ssh_client.open_sftp()
                if self.sftp_client:
                    self.sftp_client.get_channel().settimeout(300)
                self.last_used = time.time()
                return True
        except Exception as e:
            logger.error(f"连接失败 {self.host}:{self.port} - {e}")
            self.close()
            return False

    def is_active(self) -> bool:
        """检查连接是否仍然有效"""
        try:
            with self.lock:
                if self.ssh_client is None or self.sftp_client is None:
                    return False

                # 检查SSH连接是否活跃
                if not self.ssh_client.get_transport() or not self.ssh_client.get_transport().is_active():
                    return False

                # 尝试执行一个简单的命令来检查连接
                self.ssh_client.exec_command('echo test', timeout=5)
                return True
        except Exception:
            return False

    def close(self):
        """关闭连接"""
        try:
            with self.lock:
                if self.sftp_client:
                    try:
                        self.sftp_client.close()
                    except:
                        pass
                    self.sftp_client = None

                if self.ssh_client:
                    try:
                        self.ssh_client.close()
                    except:
                        pass
                    self.ssh_client = None
        except Exception:
            pass

    def __enter__(self):
        """上下文管理器入口"""
        self.in_use = True
        self.last_used = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.in_use = False
        self.last_used = time.time()

    def get_file_md5(self, remote_path: str) -> str:
        """获取远程文件的MD5（通过执行远程命令）"""
        try:
            
            command = f"md5sum {remote_path} 2>/dev/null || md5 {remote_path} 2>/dev/null || echo ''"
            stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=10)
            output = stdout.read().decode().strip()

            if output:
                # 提取MD5值
                parts = output.split()
                if parts:
                    for part in parts:
                        if len(part) == 32 and all(c in '0123456789abcdef' for c in part.lower()):
                            return part.lower()
            return ""
        except Exception as e:
            logger.warning(f"尝试获取文件 {remote_path} 的MD5值失败: {e}")
            return ""


class SFTPConnectionPool:
    """SFTP连接池"""

    def __init__(self, host: str, port: int, username: str, password: str,
                 max_size: int = 10, idle_timeout: int = 300):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.max_size = max_size
        self.idle_timeout = idle_timeout
        self.pool = queue.Queue(maxsize=max_size)
        self.active_connections = 0
        self.lock = threading.Lock()
        self.cleanup_thread = None
        self.running = True

        # 启动清理线程
        self.start_cleanup_thread()

    def start_cleanup_thread(self):
        """启动连接清理线程"""

        def cleanup_worker():
            while self.running:
                try:
                    time.sleep(60)  # 每分钟检查一次
                    self._cleanup_idle_connections()
                except Exception as e:
                    logger.warning(f"连接池清理线程异常: {e}")

        self.cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self.cleanup_thread.start()

    def _cleanup_idle_connections(self):
        """清理空闲超时的连接"""
        try:
            # 暂时将连接取出检查
            temp_connections = []
            while not self.pool.empty():
                try:
                    conn = self.pool.get_nowait()
                    temp_connections.append(conn)
                except queue.Empty:
                    break

            # 检查每个连接
            valid_connections = []
            for conn in temp_connections:
                # 检查是否空闲超时
                if time.time() - conn.last_used > self.idle_timeout:
                    logger.debug(f"关闭空闲超时连接: {conn.host}:{conn.port}")
                    conn.close()
                    with self.lock:
                        self.active_connections -= 1
                else:
                    valid_connections.append(conn)

            # 将有效连接放回池中
            for conn in valid_connections:
                try:
                    self.pool.put_nowait(conn)
                except queue.Full:
                    conn.close()
                    with self.lock:
                        self.active_connections -= 1

        except Exception as e:
            logger.warning(f"清理空闲连接时出错: {e}")

    def get_connection(self, timeout: int = 30) -> Optional[SFTPConnection]:
        """从连接池获取一个连接"""
        try:
            # 首先尝试从池中获取
            try:
                conn = self.pool.get(timeout=1)
                if conn.is_active():
                    return conn
                else:
                    # 连接无效，关闭并创建新的
                    conn.close()
                    with self.lock:
                        self.active_connections -= 1
            except queue.Empty:
                pass

            # 创建新连接
            with self.lock:
                if self.active_connections < self.max_size:
                    conn = SFTPConnection(self.host, self.port, self.username, self.password)
                    if conn.connect():
                        self.active_connections += 1
                        return conn

            # 如果无法创建新连接，等待池中的连接
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    conn = self.pool.get(timeout=1)
                    if conn.is_active():
                        return conn
                    else:
                        conn.close()
                        with self.lock:
                            self.active_connections -= 1
                except queue.Empty:
                    time.sleep(0.1)

            logger.error(f"获取连接超时: {self.host}:{self.port}")
            return None

        except Exception as e:
            logger.error(f"获取连接失败: {self.host}:{self.port} - {e}")
            return None

    def return_connection(self, conn: SFTPConnection):
        """将连接归还到连接池"""
        try:
            if conn and conn.is_active():
                # 重置连接状态
                conn.in_use = False
                conn.last_used = time.time()

                # 尝试归还到池中
                try:
                    self.pool.put_nowait(conn)
                except queue.Full:
                    # 池已满，关闭连接
                    conn.close()
                    with self.lock:
                        self.active_connections -= 1
            else:
                # 连接无效或为空，关闭它
                if conn:
                    conn.close()
                with self.lock:
                    if conn and hasattr(conn, 'in_use') and conn.in_use:
                        self.active_connections -= 1
        except Exception as e:
            logger.warning(f"归还连接时出错: {e}")
            if conn:
                conn.close()
            with self.lock:
                if conn and hasattr(conn, 'in_use') and conn.in_use:
                    self.active_connections -= 1

    def close_all(self):
        """关闭所有连接"""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)

        # 确保池中所有连接都被关闭
        connections_to_close = []
        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                connections_to_close.append(conn)
            except queue.Empty:
                break
        
        # 关闭所有连接
        for conn in connections_to_close:
            if conn:
                conn.close()

        with self.lock:
            self.active_connections = 0


class SFTPClient:
    """SFTP客户端封装类 - 使用连接池"""

    def __init__(self, connection_pool: SFTPConnectionPool):
        self.connection_pool = connection_pool
        self.current_connection = None

    def __enter__(self):
        """上下文管理器入口"""
        self.current_connection = self.connection_pool.get_connection()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        if self.current_connection:
            self.connection_pool.return_connection(self.current_connection)
            self.current_connection = None

    def list_files(self, remote_dir: str, pattern: str, recursive: bool, batch_size: int):
        """列出远程目录中的文件（支持文件名模式过滤、递归和远程路径正则表达式过滤）"""
        if not self.current_connection or not self.current_connection.connect():
            logger.error(f"连接无效，无法列出目录: {remote_dir}")

        if recursive:
            yield from self._list_files_recursive(remote_dir, pattern, batch_size)
        else:
            yield from self._list_files_non_recursive(remote_dir, pattern, batch_size)


    def _list_files_non_recursive(self, remote_dir: str, pattern: str, batch_size: int):
        """列出远程目录中的文件（非递归，支持远程路径正则表达式过滤）"""
        try:
            self.current_connection.sftp_client.chdir(remote_dir)
            items = self.current_connection.sftp_client.listdir_attr('.')
            files_info = []
            for item in items:
                # 只处理文件，不处理目录
                if not (item.st_mode & 0o40000):  # 不是目录
                    if not item.filename.startswith('.'):
                        item_path = f"{remote_dir.rstrip('/')}/{item.filename}"
                        
                        # 检查远程路径正则表达式
                        if pattern and not re.match(pattern, item.filename):
                            continue
                        files_info.append(
                            {
                                'size': item.st_size,
                                'mtime': item.st_mtime,
                                'filename': item.filename,
                                'path': item_path
                            }
                        )
                        if len(files_info) >= batch_size:
                            yield files_info
                            files_info = []
            if files_info and len(files_info) > 0:
                yield files_info
        except Exception as e:
            logger.error(f"列出目录失败 {remote_dir}: {e}")

    def _list_files_recursive(self, remote_dir: str, pattern: str, batch_size: int):
        """递归列出远程目录中的文件（支持文件名模式过滤和远程路径正则表达式过滤）"""

        try:
            # 使用栈来遍历目录结构
            dir_stack = [remote_dir]
            files_info = []
            while dir_stack:
                current_dir = dir_stack.pop()

                try:
                    items = self.current_connection.sftp_client.listdir_attr(current_dir)

                    for item in items:
                        item_path = f"{current_dir.rstrip('/')}/{item.filename}"
                        
                        # 判断是否为目录
                        if item.st_mode & 0o40000:  # 是目录
                            # 跳过隐藏目录
                            if not item.filename.startswith('.'):
                                dir_stack.append(item_path)  # 将子目录加入栈中
                        else:  # 是文件
                            # 跳过隐藏文件
                            if not item.filename.startswith('.'):
                                # 检查正则表达式
                                if item_path.startswith(remote_dir):
                                    relative_path = item_path[len(remote_dir):].lstrip('/')
                                else:
                                    relative_path = item_path.lstrip('/')
                                if pattern and not re.search(pattern, relative_path):
                                    continue
                                files_info.append(
                                    {
                                        'size': item.st_size,
                                        'mtime': item.st_mtime,
                                        'path': item_path,
                                        'filename': item.filename,
                                        'relative_path': relative_path
                                    }
                                )
                                if len(files_info) >= batch_size:
                                    yield files_info
                                    files_info = []
                except OSError as e:
                    logger.warning(f"访问目录失败 {current_dir}: {e}")
                    continue
            if files_info and len(files_info) > 0:
                yield files_info
        except Exception as e:
            logger.error(f"递归列出目录失败 {remote_dir}: {e}")

    def download_file(self, remote_path: str, local_path: str, preserve_timestamps: bool = True) -> bool:
        """下载单个文件"""
        if not self.current_connection or not self.current_connection.connect():
            logger.error(f"连接无效，无法下载文件: {remote_path}")
            return False

        try:
            Path(local_path).parent.mkdir(parents=True, exist_ok=True)
            self.current_connection.sftp_client.get(remote_path, local_path)

            if preserve_timestamps:
                remote_attr = self.current_connection.sftp_client.stat(remote_path)
                os.utime(local_path, (remote_attr.st_atime, remote_attr.st_mtime))

            return True
        except Exception as e:
            logger.error(f"下载文件失败 {remote_path}: {e}")
            return False


class SFTPConfig:
    """SFTP配置管理类"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = self._load_config()

    def _load_config(self):
        """加载配置文件"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)

            if 'servers' not in config:
                logger.error("配置文件必须包含 'servers' 部分")
                sys.exit(1)

            return config
        except FileNotFoundError:
            logger.error(f"配置文件不存在: {self.config_file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logger.error(f"配置文件解析失败: {e}")
            sys.exit(1)

    def _process_value(self, value):
        """递归处理配置值中的表达式"""
        if isinstance(value, str):
            return ExpressionProcessor.process_path(value)
        elif isinstance(value, dict):
            return {k: self._process_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._process_value(item) for item in value]
        else:
            return value

    def process_all_expressions(self):
        """处理所有配置项中的表达式"""
        self.config = self._process_value(self.config)

    def get(self, key: str, default=None):
        """获取全局配置项"""
        return self.config.get(key, default)

    def get_server(self, server_name: str) -> Dict:
        """获取服务器配置"""
        servers = self.config.get('servers', None)
        if not servers:
            logger.error("配置文件必须包含 'servers' 部分")
            sys.exit(1)
        server_config = servers.get(server_name, None)
        if not server_config:
            logger.error(f"服务器 '{server_name}' 不存在")
            sys.exit(1)
        return server_config

    def get_all_servers(self) -> List[str]:
        """获取所有服务器名称"""
        return list(self.config.get('servers', {}).keys())

    def validate_server_config(self, server_name: str) -> bool:
        """验证服务器配置是否完整"""
        server_config = self.get_server(server_name)
        
        # 验证基本连接字段
        required_basic_fields = ['host', 'port', 'username', 'password']
        for field in required_basic_fields:
            if not server_config.get(field):
                logger.error(f"服务器 '{server_name}' 缺少配置字段: {field}")
                return False
        
        # 验证备份设置数组
        backup_settings = server_config.get('backup_settings', [])
        if not backup_settings:
            logger.error(f"服务器 '{server_name}' 缺少 backup_settings 配置")
            return False
        
        # 验证每个备份设置的必要字段
        required_setting_fields = ['remote_dir', 'backup_dir']
        for i, setting in enumerate(backup_settings):
            for field in required_setting_fields:
                if not setting.get(field):
                    logger.error(f"服务器 '{server_name}' 的第 {i+1} 个备份设置缺少字段: {field}")
                    return False
        
        return True


class FileManager:
    """文件同步管理器"""

    def __init__(self, config: SFTPConfig, decryptor: PasswordDecryptor):
        self.config = config
        self.decryptor = decryptor
        self.batch_delay = config.get('batch_delay')
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 30)
        self.max_threads = config.get('max_threads', 5)
        self.temp_dir = config.get('temp_dir')  # 临时目录配置
        self.connection_pools = {}  # 连接池缓存

    def _get_connection_pool(self, server_config: Dict) -> SFTPConnectionPool:
        """获取或创建连接池"""
        server_key = f"{server_config['host']}:{server_config['port']}:{server_config['username']}"

        if server_key not in self.connection_pools:
            # 解密密码
            password = self.decryptor.decrypt(server_config['password'])

            # 创建连接池
            pool = SFTPConnectionPool(
                host=server_config['host'],
                port=server_config['port'],
                username=server_config['username'],
                password=password,
                max_size=self.max_threads * 2,  # 连接池大小为线程数的两倍
                idle_timeout=300
            )
            self.connection_pools[server_key] = pool

        return self.connection_pools[server_key]

    def close_all_connections(self):
        """关闭所有连接池"""
        for pool in self.connection_pools.values():
            pool.close_all()
        self.connection_pools.clear()

    def _calculate_local_file_md5(self, file_path: str) -> str:
        """计算本地文件的MD5"""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"计算本地文件MD5失败 {file_path}: {e}")
            return ""

    def _calculate_remote_file_md5(self, remote_path: str) -> str:
        """获取远程文件的MD5"""
        # 通过连接池获取一个连接来计算远程文件MD5
        # 遍历connection_pools找到适合的连接
        for pool in self.connection_pools.values():
            # 尝试获取一个连接
            conn = pool.get_connection()
            if conn:
                try:
                    # 使用连接计算远程文件MD5
                    with SFTPClient(pool) as client:
                        if client.current_connection:
                            return client.current_connection.get_file_md5(remote_path)
                finally:
                    pool.return_connection(conn)
        return ""

    def __get_local_file_info(self, file_path: str) -> Dict:
        """获取本地文件信息"""
        try:
            stat = os.stat(file_path)
            info: Dict = {'size': stat.st_size, 'mtime': stat.st_mtime, 'path': file_path}
            return info
        except:
            return {}

    def is_file_already_backed_up(self, local_file_info: Dict, remote_file_info: Dict, check_by_md5: bool) -> bool:
        """检查文件是否已经备份"""

        try:
            # 检查文件大小是否一致
            if local_file_info['size'] != remote_file_info['size']:
                return False

            # 如果配置了MD5检查，则验证MD5
            if check_by_md5:
                # 获取本地文件MD5
                local_md5 = self._calculate_local_file_md5(local_file_info.get('path'))
                # 获取远程文件MD5
                remote_md5 = self._calculate_remote_file_md5(remote_file_info['path'])
                return local_md5 == remote_md5
            return True
        except Exception:
            return False

    def download_file_with_retry(self, connection_pool: SFTPConnectionPool, remote_info: Dict,
                                 filename: str, backup_dir: str, check_by_md5: bool = False, recursive: bool = False) -> bool:
        """下载单个文件（带重试机制）- 使用临时目录"""
        # 计算实际备份路径，如果启用了递归下载，需要保持目录结构
        if recursive and 'relative_path' in remote_info:
            # 使用相对路径保持目录结构
            relative_path = remote_info['relative_path']
            final_filename = relative_path
            backup_file = Path(backup_dir) / relative_path
            
            # 使用临时目录 - 临时文件直接放在temp_dir根目录，使用完整路径作为文件名的一部分
            if self.temp_dir:
                temp_dir_path = Path(self.temp_dir)
                # 将路径分隔符替换为下划线或其他字符，避免在temp_dir中创建子目录
                safe_temp_filename = str(Path(relative_path)).replace('/', '_').replace('\\', '_') + TEMP_EXTENSION
                temp_file = temp_dir_path / safe_temp_filename
            else:
                temp_file = Path(backup_dir) / f"{relative_path}{TEMP_EXTENSION}"
        else:
            # 非递归模式，文件放在备份目录根目录
            final_filename = filename
            temp_filename = f"{filename}{TEMP_EXTENSION}"
            backup_file = Path(backup_dir) / final_filename
            
            # 使用临时目录 - 临时文件直接放在temp_dir根目录
            if self.temp_dir:
                temp_dir_path = Path(self.temp_dir)
                temp_file = temp_dir_path / temp_filename
            else:
                temp_file = Path(backup_dir) / temp_filename

        # 确保目录存在
        backup_file.parent.mkdir(parents=True, exist_ok=True)
        # 只有当不使用temp_dir时才创建临时文件的父目录
        if not self.temp_dir:
            temp_file.parent.mkdir(parents=True, exist_ok=True)

        # 如果最终文件已存在，检查是否需要重新下载
        if backup_file.exists():
            local_info = self.__get_local_file_info(str(backup_file))
            if self.is_file_already_backed_up(local_info, remote_info, check_by_md5):
                logger.info(f"文件已存在且完整: {final_filename}")
                return True

        # 清理可能存在的临时文件
        if temp_file.exists():
            try:
                temp_file.unlink()
                logger.info(f"清理旧临时文件: {str(temp_file)}")
            except Exception as e:
                logger.warning(f"清理临时文件失败: {str(temp_file)} - {e}")

        for attempt in range(self.max_retries):
            try:
                logger.info(f"开始下载: {final_filename} (尝试 {attempt + 1}/{self.max_retries})")

                # 使用连接池下载到临时文件
                with SFTPClient(connection_pool) as client:
                    if client.download_file(remote_info['path'], str(temp_file),
                                            self.config.get('preserve_timestamps', True)):

                        # 检查临时文件大小
                        if temp_file.exists() and temp_file.stat().st_size == remote_info['size']:
                            # 下载成功，移动临时文件到最终位置
                            try:
                                # 如果目标文件已存在，先删除
                                if backup_file.exists():
                                    backup_file.unlink()

                                # 确保目标目录存在
                                backup_file.parent.mkdir(parents=True, exist_ok=True)
                                
                                # 移动临时文件到最终位置
                                shutil.move(str(temp_file), str(backup_file))
                                logger.info(f"✓ 文件已下载并移动到: {final_filename}")

                                # 如果配置了保持时间戳，设置时间戳
                                if self.config.get('preserve_timestamps', True):
                                    with SFTPClient(connection_pool) as timestamp_client:
                                        remote_attr = timestamp_client.current_connection.sftp_client.stat(
                                            remote_info['path'])
                                        os.utime(str(backup_file), (remote_attr.st_atime, remote_attr.st_mtime))

                                return True
                            except Exception as e:
                                logger.error(f"移动临时文件失败 {str(temp_file)} -> {final_filename}: {e}")
                        else:
                            logger.error(
                                f"临时文件大小不匹配: {str(temp_file)} ({temp_file.stat().st_size if temp_file.exists() else 0} != {remote_info['size']})")
                    else:
                        logger.error(f"下载失败: {final_filename}")

            except Exception as e:
                logger.warning(f"下载失败: {final_filename} - {e}")

            # 清理失败的临时文件
            if attempt < self.max_retries - 1:
                if temp_file.exists():
                    try:
                        temp_file.unlink()
                    except:
                        pass
                time.sleep(self.retry_delay)
            else:
                # 最后一次尝试后清理
                if temp_file.exists():
                    try:
                        temp_file.unlink()
                        logger.info(f"清理失败的临时文件: {str(temp_file)}")
                    except:
                        pass

        return False

    @staticmethod
    def cleanup_temp_files(temp_dir: str):
        """清理备份目录和临时目录中的临时文件（递归清理子目录）"""
        # 如果指定了临时目录，也清理临时目录中的临时文件
        if temp_dir:
            temp_path = Path(temp_dir)
            if temp_path.exists():
                try:
                    temp_path.unlink()
                    logger.info(f"已删除临时目录: {temp_dir}")
                except Exception as e:
                    logger.error(f"删除临时目录失败 {temp_dir}: {e}")

    def download_files(self, server_config: Dict) -> bool:
        """从服务器下载文件"""
        # 获取连接池
        connection_pool = self._get_connection_pool(server_config)

        # 获取备份设置数组
        backup_settings = server_config.get('backup_settings', [])
        
        if not backup_settings:
            logger.error("服务器配置中没有 backup_settings 配置")
            return False
        
        overall_success = True
        
        # 遵循 backup_settings 数组，处理每一个备份设置
        for setting in backup_settings:
            # 获取各配置项
            remote_dir = setting.get('remote_dir')
            backup_dir = setting.get('backup_dir')
            pattern = setting.get('pattern')
            recursive = setting.get('recursive', False)
            check_by_md5 = setting.get('check_by_md5', False)
            batch_size = setting.get('batch_size', 1000)

            if not remote_dir or not backup_dir:
                logger.error(f"备份设置中缺少 remote_dir 或 backup_dir 配置: {setting}")
                overall_success = False
                continue

            # 处理filename配置项（支持表达式）
            if pattern:
                # 使用PathExpressionProcessor处理表达式
                pattern = ExpressionProcessor.process_path(pattern)

            try:
                # 首先获取远程文件列表
                with SFTPClient(connection_pool) as client:
                    # 处理远程目录
                    logger.info(f"远程目录: {remote_dir}")
                    if pattern:
                        logger.info(f"正则要求: {pattern}")
                    logger.info(f"备份目录: {backup_dir}")
                    logger.info(f"每个批次获取的文件数量: {batch_size}")
                    logger.info(f"递归下载: {recursive}")
                    logger.info(f"MD5校验: {check_by_md5}")

                    # 获取远程文件列表

                    total_size = 0
                    batch = 1
                    success = 0
                    fail = 0

                    for remote_files_info in client.list_files(remote_dir, pattern, recursive, batch_size):
                        if not remote_files_info:
                            logger.info(f"远程目录为空: {remote_dir}")
                            continue
                        total_size += len(remote_files_info)
                        logger.info(f"已获取第 {batch} 批文件, 当前批次数量: {len(remote_files_info)}, 已获取总数量: {total_size}")

                        # 使用线程池下载
                        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                            futures = []

                            for remote_file in remote_files_info:
                                futures.append(executor.submit(
                                    self._download_file_task,
                                    connection_pool,
                                    remote_file,
                                    remote_file['filename'],
                                    backup_dir,
                                    check_by_md5,
                                    recursive
                                ))

                            for future in as_completed(futures):
                                if future.result():
                                    success += 1
                                else:
                                    fail += 1

                        # 批次间的延迟
                        logger.info(f"已处理第 {batch} 批文件, 等待 {self.batch_delay} 秒")
                        time.sleep(self.batch_delay)

                        batch += 1

                    logger.info(f"处理完成 文件总数量 {total_size} 成功 {success}, 失败 {fail}")

                    if fail > 0:
                        overall_success = False

            except Exception as e:
                logger.error(f"下载过程中发生错误: {e}")
                # 发生错误时也清理临时文件
                overall_success = False
                continue
        
        return overall_success

    def _download_file_task(self, connection_pool: SFTPConnectionPool, remote_info: Dict,
                            filename: str, backup_dir: str, check_by_md5: bool = False, recursive_download: bool = False) -> bool:
        """单个文件下载任务（在线程中执行）"""
        try:
            return self.download_file_with_retry(connection_pool, remote_info, filename, backup_dir, check_by_md5, recursive_download)
        except Exception as e:
            logger.error(f"文件下载任务失败 {filename}: {e}")
            return False


class SFTPFileSync:
    """SFTP文件同步主类"""

    def __init__(self):
        self.args = self._parse_arguments()
        self.config = SFTPConfig(self.args.config)
        self.decryptor = PasswordDecryptor()

        self._setup_logging()
        logger.info(f"已加载配置文件: {self.args.config}")

        self.config.process_all_expressions()
        self._cleanup_temp_files()


    def _setup_logging(self):
        """配置日志系统"""
        logger.setLevel(logging.INFO)

        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        # 文件处理器（可选）
        log_dir = self.config.get('log_dir')
        if log_dir:
            # 处理日志目录中的表达式
            log_dir = ExpressionProcessor.process_path(log_dir)
            Path(log_dir).mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = Path(log_dir) / f"sftp_sync_{timestamp}.log"

            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.INFO)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)

    @staticmethod
    def _parse_arguments():
        """解析命令行参数"""
        parser = argparse.ArgumentParser(description="SFTP文件同步工具")
        parser.add_argument('--server', required=True, help='配置文件中的服务器名称')
        parser.add_argument('--config', default=CONFIG_FILE, help=f'配置文件路径 (默认: {CONFIG_FILE})')
        return parser.parse_args()

    def _cleanup_temp_files(self):
        """清理临时文件"""
        temp_dir = self.config.get('temp_dir')
        if temp_dir:
            temp_path = Path(temp_dir)
            if temp_path.exists():
                try:
                    shutil.rmtree(str(temp_path))
                    logger.info(f"已删除临时目录: {temp_dir}")
                except Exception as e:
                    logger.error(f"删除临时目录失败 {temp_dir}: {e}")
                logger.info("临时文件清理完成")

    def run(self):
        """运行同步任务"""
        try:
            # 显示处理的路径
            server_name = self.args.server
            if not self.config.validate_server_config(server_name):
                sys.exit(1)

            logger.info("=" * 50)
            logger.info(f"开始同步服务器: {server_name}")
            logger.info("=" * 50)

            # 同步服务器
            sync_manager = FileManager(self.config, self.decryptor)
            overall_success = True

            logger.info("-" * 30)
            logger.info(f"正在同步服务器: {server_name}")
            logger.info("-" * 30)

            server_config = self.config.get_server(server_name)
            success = sync_manager.download_files(server_config)

            if success:
                logger.info(f"服务器 '{server_name}' 同步完成")
            else:
                logger.error(f"服务器 '{server_name}' 同步失败")

            # 同步完成后关闭所有连接
            sync_manager.close_all_connections()
            sys.exit(0 if overall_success else 1)
        except KeyboardInterrupt:
            logger.info("用户中断操作")
            sys.exit(1)
        except Exception as e:
            logger.error(f"未预期的错误: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
        finally:
            self._cleanup_temp_files()


def main():
    """主函数"""
    logger.info("=== SFTP文件同步工具 ===")
    SFTPFileSync().run()


if __name__ == '__main__':
    main()