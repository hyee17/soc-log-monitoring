from collections import defaultdict

failed_attempts = defaultdict(int)
blocked_ips = set()
THRESHOLD = 3

with open("auth_logs.txt", "r") as file:
    for line in file:
        parts = line.strip().split()

        # Skip invalid log lines
        if len(parts) < 5:
            continue

        timestamp = parts[0] + " " + parts[1]
        event = parts[2]
        user = parts[3]
        ip = parts[4]

        # If IP already blocked, ignore further activity
        if ip in blocked_ips:
            continue

        if event == "LOGIN_FAILED":
            failed_attempts[ip] += 1

            # Trigger alert only once at threshold
            if failed_attempts[ip] == THRESHOLD:
                alert_message = (
                    f"[ALERT] Possible brute-force attack detected!\n"
                    f"IP: {ip}\n"
                    f"Failed Attempts: {failed_attempts[ip]}\n"
                    f"Time: {timestamp}\n"
                    + "-" * 50
                )

                print(alert_message)

                # Save alert to file
                with open("alerts.txt", "a") as alert_file:
                    alert_file.write(alert_message + "\n")

                # Block IP
                blocked_ips.add(ip)
                print(f"[ACTION] IP {ip} has been blocked")

        elif event == "LOGIN_SUCCESS":
            # Reset counter on successful login
            failed_attempts[ip] = 0
