import socket
import json
import datetime

# Rrjeti dhe porta
HOST = "0.0.0.0"
PORT = 5000
LOG_FILE = "received_logs.json"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print(f"[+] Waiting for LOGS on port {PORT}...\n")

while True:
    data, addr = sock.recvfrom(65535)
    try:
        decoded = data.decode("utf-8")
        try:
            log = json.loads(decoded)
        except json.JSONDecodeError:
            log = {"raw": decoded}
    except Exception:
        log = {"raw": str(data)}

    log["source_ip"] = addr[0]
    log["timestamp"] = datetime.datetime.now().isoformat()

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log) + "\n")

    print(f"[{addr[0]}] New Log ({len(data)} byte)")
