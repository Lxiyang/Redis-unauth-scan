#!/usr/bin/env python
# coding=utf-8
# author: B1anda0

import socket
import sys
import colorama
import time
import logging
from colorama import init, Fore

# 初始化 Colorama
init(autoreset=True)

# banner
banner = r'''
{} _____          _ _                                    _   _     
|  __ \        | (_)                                  | | | |    
| |__) |___  __| |_ ___ ______ _   _ _ __   __ _ _   _| |_| |__  
|  _  // _ \/ _` | / __|______| | | | '_ \ / _` | | | | __| '_ \ 
| | \ \  __/ (_| | \__ \      | |_| | | | | (_| | |_| | |_| | | |
|_|  \_\___|\__,_|_|___/       \__,_|_| |_|\__,_|\__,_|\__|_| |_| 
'''.format(Fore.CYAN)

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

def time_file():
    """生成带时间戳的文件名"""
    return f"result_{int(time.time())}.txt"

def check(ip, port, results_file, timeout=10):
    """检查指定 IP 和端口的 Redis 未授权漏洞"""
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout) as s:
            payload = 'info\r\n'
            s.sendall(payload.encode())
            result = s.recv(1024)
            if b'redis_version' in result:
                logger.info(f"{Fore.RED}[+] {ip}:{port} 存在 Redis 未授权漏洞{Fore.RESET}")
                with open(results_file, 'a') as file:
                    file.write(f"{ip}:{port}\n")
            else:
                logger.info(f"[-] {ip}:{port} 未发现 Redis 未授权漏洞")
    except (socket.error, socket.timeout) as e:
        logger.error(f"[-] Error checking {ip}:{port}: {e}")

def print_help():
    """显示帮助信息"""
    print('''Usage:
                 python Redis-unauth-scan.py -u ip:port
                 python Redis-unauth-scan.py -r url.txt
              ''')

def validate_ip_port(ip_port):
    """验证 ip:port 格式是否正确"""
    if len(ip_port) == 2:
        return ip_port[0], ip_port[1]
    else:
        logger.error('格式错误！')
        return None, None

def scan_single(ip, port, results_file):
    """扫描单个 IP 和端口"""
    check(ip, port, results_file)

def scan_from_file(file_name, results_file):
    """从文件中扫描多个 IP 和端口"""
    try:
        with open(file_name, 'r') as file:
            for line in file:
                ip_port = line.strip().split(':')
                ip, port = validate_ip_port(ip_port)
                if ip and port:
                    check(ip, port, results_file)
        logger.info('Scan Over')
    except FileNotFoundError:
        logger.error(f"File {file_name} not found.")
    except Exception as e:
        logger.error(f"Error reading file {file_name}: {e}")

if __name__ == '__main__':
    print(banner)
    
    if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help']:
        print_help()
    elif sys.argv[1] == '-u':
        ip_port = sys.argv[2].split(':')
        ip, port = validate_ip_port(ip_port)
        if ip and port:
            results_file = time_file()
            scan_single(ip, port, results_file)
    elif sys.argv[1] == '-r':
        file_name = sys.argv[2]
        results_file = time_file()
        scan_from_file(file_name, results_file)
    else:
        logger.error('参数错误！')
        print_help()
