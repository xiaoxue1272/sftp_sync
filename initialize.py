#!/usr/bin/env python3
"""
SFTP同步工具安装脚本
"""

import os
import sys
import subprocess
from pathlib import Path


def check_dependencies():
    """检查依赖"""
    print("检查依赖...")

    dependencies = {
        'paramiko': 'paramiko',
        'cryptography': 'cryptography'
    }

    missing_deps = []

    for pkg_name, import_name in dependencies.items():
        try:
            __import__(import_name)
            print(f"  ✓ {pkg_name}")
        except ImportError:
            missing_deps.append(pkg_name)
            print(f"  ✗ {pkg_name}")

    return missing_deps

def install_dependencies():
    """安装依赖"""
    print("\n安装Python依赖...")

    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ])
        print("依赖安装成功")
        return True
    except subprocess.CalledProcessError as e:
        print(f"依赖安装失败: {e}")
        return False

def create_example_config():
    """创建示例配置文件"""
    config_path = Path('sftp_config.json')


    if not config_path.exists():
        print("\n创建示例配置文件...")

        example_config = '''{
  "temp_dir": "./temp",
  "log_dir": "./logs",
  "batch_size": 1000,
  "batch_delay": 30,
  "max_retries": 3,
  "max_threads": 10,
  "retry_delay": 30,
  "preserve_timestamps": true,

  "servers": {
    "test": {
      "host": "sftp.host.com",
      "port": 22,
      "username": "sftp_user",
      "password": "",
      "backup_settings": [
        {
          "remote_dir": "/upload/test/",
          "backup_dir": "./backup/test",
          "pattern": ".*\\.txt$",
          "recursive": false,
          "check_by_md5": false,
          "batch_size": 1000
        }
      ]
    }
  }
}'''

        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(example_config)

        os.chmod(config_path, 0o600)
        print(f"  创建: {config_path}")

def create_crontab_example():
    """创建crontab示例"""
    print("\n创建crontab示例...")

    crontab_example = """
    
# SFTP文件同步定时任务

# 同步：每天凌晨2点，从服务器同步文件
0 2 * * * cd /path/to/sftp_sync && python main.py --server test
    
# 清理日志：每月1号凌晨4点，清理30天前的日志
0 4 1 * * find ./logs -name "*.log" -mtime +30 -delete
    
"""

    crontab_file = 'sftp_crontab_example.txt'
    with open(crontab_file, 'w', encoding='utf-8') as f:
        f.write(crontab_example)

    print(f"  crontab示例: {crontab_file}")

def generate_rsa_keys():
    """生成RSA密钥对"""
    print("\n生成RSA密钥对...")
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        # 生成私钥
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024  # 1024位密钥
        )

        # 序列化私钥
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # 保存私钥
        private_key_file = ".encrypt_private.pem"
        with open(private_key_file, 'wb') as f:
            f.write(private_pem)

        # 设置文件权限
        os.chmod(private_key_file, 0o600)

        print(f"  ✓ RSA私钥已生成: {private_key_file}")

    except ImportError:
        print("  注意: 请先安装cryptography库再生成密钥")
        print("  运行: pip install cryptography")

def main():
    """主安装函数"""
    print("=== SFTP同步工具安装 ===\n")

    # 检查Python版本
    if sys.version_info < (3, 6):
        print("错误: 需要Python 3.6或更高版本")
        sys.exit(1)

    # 检查依赖
    missing_deps = check_dependencies()

    if missing_deps:
        print(f"\n缺少依赖: {', '.join(missing_deps)}")
        choice = input("是否自动安装? (y/n): ").lower()

        if choice == 'y':
            if not install_dependencies():
                print("安装依赖失败，请手动安装:")
                print("  pip install -r requirements.txt")
                sys.exit(1)
        else:
            print("请手动安装依赖:")
            print("  pip install -r requirements.txt")
            sys.exit(1)

    # 创建示例配置
    create_example_config()

    # 生成RSA密钥对
    generate_rsa_keys()

    # 创建crontab示例
    create_crontab_example()

    # 完成信息
    print("\n" + "=" * 50)
    print("安装完成!")
    print("=" * 50)

    print("\n下一步操作:")
    print("1. 使用rsa_encrypt.py加密SFTP密码:")
    print("   python rsa_encrypt.py --generate  # 生成密钥对（如果未生成）")
    print("   python rsa_encrypt.py 'your_password'  # 加密密码")
    print("")
    print("2. 编辑配置文件 sftp_config.json，填入加密后的密码")
    print("   注意: 配置文件中新增了temp_dir配置项，用于指定临时文件存储目录，以及batch_delay配置项，用于设置批次间延迟时间（秒）")
    print("")
    print("3. 测试同步:")
    print("   python main.py --server test")
    print("")
    print("4. 配置定时任务（可选）:")
    print("   crontab -e")
    print("   (添加 sftp_crontab_example.txt 中的内容)")
    print("")


if __name__ == '__main__':
    main()