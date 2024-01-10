#!/usr/bin/env python
# coding=utf-8
# author:B1anda0

import socket
import sys
from colorama import Fore, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from tqdm import tqdm  
import argparse

init(autoreset=True)

banner = '''
{} _____          _ _                                    _   _     
|  __ \        | (_)                                  | | | |    
| |__) |___  __| |_ ___ ______ _   _ _ __   __ _ _   _| |_| |__  
|  _  // _ \/ _` | / __|______| | | | '_ \ / _` | | | | __| '_ \ 
| | \ \  __/ (_| | \__ \      | |_| | | | | (_| | |_| | |_| | | |
|_|  \_\___|\__,_|_|___/       \__,_|_| |_|\__,_|\__,_|\__|_| |_|
'''.format(Fore.CYAN)

def check(ip, port, timeout=10, lock=None):
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout) as s:
            payload = 'info\r\n'
            s.sendall(payload.encode())
            result = s.recv(1024)
            with lock:
                if b'redis_version' in result:
                    # Check if Redis server requires authentication
                    s.sendall('config get requirepass\r\n'.encode())
                    requirepass_result = s.recv(1024)
                    if b'requirepass' in requirepass_result and b'""' in requirepass_result:
                        print(u"\033[1;31;40m[+]{}:{} 存在未授权访问漏洞".format(ip, port))
                        return (ip, port)
                    else:
                        print(u"{}:{} Redis服务器存在密码保护，不是未授权访问漏洞".format(ip, port))
    except (socket.error, socket.timeout):
        with lock:
            pass  
    return None

def scan_multiple_ips(filename, threads):
    print(banner)  # Print the banner once at the beginning
    vulnerable_ips = []  

    try:
        with open(filename, 'r') as file:
            total_lines = sum(1 for line in file)

        with open(filename, 'r') as file:
            lock = Lock()  
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(check, *line.strip().split(':'), timeout=10, lock=lock): line for line in file}
                try:
                    for _ in tqdm(as_completed(futures), total=total_lines, desc="扫描进度", dynamic_ncols=True):
                        pass

                    # 获取扫描结果
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            vulnerable_ips.append(result)

                except KeyboardInterrupt:
                    print("\n用户中断任务。正在清理线程...")
                    for future in futures:
                        future.cancel()

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")

    if vulnerable_ips:
        print("\n存在未授权访问漏洞的IP地址：")
        for ip, port in vulnerable_ips:
            print(f"{ip}:{port}")
    else:
        print("\n未发现存在未授权访问漏洞的IP地址。")

def scan_single_ip(ip, port, threads):
    print(banner)
    try:
        check_result = check(ip, port, timeout=10, lock=Lock())
        if check_result:
            print(f"\n存在未授权访问漏洞的IP地址：\n{check_result[0]}:{check_result[1]}")
        else:
            print("\n未发现存在未授权访问漏洞的IP地址。")

    except KeyboardInterrupt:
        print("\n用户中断任务。")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan for Redis unauthorized access vulnerability. \nThe individual IP addresses are as follows:\npython Redis-unauth-scan.py 192.168.1.1:6379 -t 15\nOr, if you have a file containing multiple IPs:\npython Redis-unauth-scan.py ip.txt -t 15')
    parser.add_argument('target', type=str, help='Target IP address and port (format: ip:port). Use this option for scanning a single IP or provide a file containing multiple IPs.')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads for concurrent scanning (default: 10).')

    args = parser.parse_args()

    if ':' in args.target:
        # If ':' is present in the target argument, assume it's an IP:Port format for scanning a single IP
        ip, port = args.target.split(':')
        scan_single_ip(ip, port, args.threads)
    else:
        # Otherwise, assume it's a file containing multiple IPs
        scan_multiple_ips(args.target, args.threads)

    print('扫描完成')
