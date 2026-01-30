#!/usr/bin/env python3
"""
RSA密码加密工具
用于加密配置文件中的SFTP密码
"""

import base64
import sys
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def encrypt_password(password: str, private_key_file: str = ".encrypt_private.pem") -> Optional[str]:
    """使用RSA公钥加密密码"""
    try:
        # 加载公钥
        with open(private_key_file, 'rb') as f:
            private_key = load_pem_private_key(f.read(), None)
            public_key = private_key.public_key()

        # 加密密码
        encrypted = public_key.encrypt(
            password.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Base64编码后返回
        return base64.b64encode(encrypted).decode()

    except FileNotFoundError:
        print(f"错误: 私钥文件不存在: {private_key_file}")
        print("请先运行主脚本生成私钥和公钥")
        return None
    except Exception as e:
        print(f"加密失败: {e}")
        return None

def generate_private_key():
    """生成RSA密钥对"""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import os

    # 生成私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )

    # 保存私钥
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    private_key_file = ".encrypt_private.pem"
    with open(private_key_file, 'wb') as f:
        f.write(private_pem)


    # 设置文件权限
    os.chmod(private_key_file, 0o600)

    print(f"✓ RSA私钥已生成:")
    print(f"\n  格式: PKCS8")
    print(f"\n  私钥文件: {private_key_file} ")
    print("\n使用方法:")
    print("  1. 使用此工具加密密码: python rsa_encrypt.py 'your_password'")
    print("  2. 将加密后的密码填入配置文件")

def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("RSA密码加密工具")
        print("")
        print("用法:")
        print("  python rsa_encrypt.py <password>              # 加密密码")
        print("  python rsa_encrypt.py --generate             # 生成私钥")
        print("  python rsa_encrypt.py --help                 # 显示帮助")
        print("")
        print("示例:")
        print("  python rsa_encrypt.py your_password")
        print("  python rsa_encrypt.py --generate")
        return

    if sys.argv[1] == "--generate":
        generate_private_key()
    elif sys.argv[1] in ["--help", "-h"]:
        print("RSA密码加密工具")
        print("用于加密配置文件中的SFTP密码")
        print("")
        print("首先需要生成密钥对:")
        print("  python rsa_encrypt.py --generate")
        print("")
        print("然后加密密码:")
        print("  python rsa_encrypt.py your_password")
        print("")
        print("将输出的加密字符串填入配置文件的password字段")
    else:
        password = sys.argv[1]
        encrypted = encrypt_password(password)
        if encrypted:
            print(f"原始密码: {password}")
            print(f"加密后: {encrypted}")
            print("")
            print("请将以上加密字符串填入配置文件的password字段:")
            print(f"  password: \"{encrypted}\"")

if __name__ == '__main__':
    main()