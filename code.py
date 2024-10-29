logs = [
    "[2024-10-03 12:35:00] - LOGIN ATTEMPT - User: admin - IP: 192.168.1.100 - Status: SUCCESS",
    "[2024-10-03 12:36:00] - LOGIN ATTEMPT - User: admin - IP: 192.168.1.100 - Status: FAILED",
    "[2024-10-03 12:37:30] - LOGIN ATTEMPT - User: admin - IP: 192.168.1.100 - Status: FAILED",
    "[2024-10-03 12:38:00] - LOGIN ATTEMPT - User: guest - IP: 10.0.0.1 - Status: FAILED",
    "[2024-10-03 12:39:15] - LOGIN ATTEMPT - User: admin - IP: 192.168.1.100 - Status: FAILED"
]
FAILED_LOGIN_THRESHOLD = 3
BLACKLISTED_IPS = ["10.0.0.1", "192.168.1.200"]
def parse_log(log_entry):
    parts = log_entry.split(" - ")
    timestamp = parts[0].strip("[]")
    action = parts[1].strip()
    user = parts[2].split(": ")[1]
    ip = parts[3].split(": ")[1]
    status = parts[4].split(": ")[1]
    return {
        "timestamp": timestamp,
        "action": action,
        "user": user,
        "ip": ip,
        "status": status
    }
def detect_failed_logins(logs):
    failed_attempts = {}
    for log in logs:
        log_info = parse_log(log)
        if log_info["status"] == "FAILED":
            user_ip = (log_info["user"], log_info["ip"])
            if user_ip not in failed_attempts:
                failed_attempts[user_ip] = 0
            failed_attempts[user_ip] += 1
            if failed_attempts[user_ip] >= FAILED_LOGIN_THRESHOLD:
                print(f"ALERT: Multiple failed login attempts for user '{log_info['user']}' from IP {log_info['ip']}")
def detect_blacklisted_ips(logs):
    for log in logs:
        log_info = parse_log(log)  
        if log_info["ip"] in BLACKLISTED_IPS:
            print(f"ALERT: Access attempt from blacklisted IP {log_info['ip']} by user '{log_info['user']}'")
def analyze_logs(logs):
    detect_failed_logins(logs)
    detect_blacklisted_ips(logs)
if __name__ == "__main__":
    print("Analyzing logs for potential threats...")
    analyze_logs(logs)
