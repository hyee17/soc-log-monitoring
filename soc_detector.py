from collections import defaultdict

failed_attempts = defaultdict(int)  # tracks how many times each IP has failed to login
blocked_ips = set()                 # IPs we've already flagged and blocked
THRESHOLD = 3                       # block after this many failed attempts

with open("auth_logs.txt", "r") as file:
    for line in file:
        parts = line.strip().split()

        # need at least 5 fields (timestamp x2, event, user, ip) — skip garbage lines
        if len(parts) < 5:
            continue

        # pull out each field by position
        timestamp = parts[0] + " " + parts[1]
        event = parts[2]
        user = parts[3]
        ip = parts[4]

        # nothing more to do for already-blocked IPs
        if ip in blocked_ips:
            continue

        if event == "LOGIN_FAILED":
            failed_attempts[ip] += 1

            # only alert once — right when they hit the threshold, not on every attempt after
            if failed_attempts[ip] == THRESHOLD:
                alert_message = (
                    f"[ALERT] Possible brute-force attack detected!\n"
                    f"IP: {ip}\n"
                    f"Failed Attempts: {failed_attempts[ip]}\n"
                    f"Time: {timestamp}\n"
                    + "-" * 50
                )

                print(alert_message)

                # append to alerts file so we have a persistent record
                with open("alerts.txt", "a") as alert_file:
                    alert_file.write(alert_message + "\n")

                # blacklist the IP so we stop processing its future log entries
                blocked_ips.add(ip)
                print(f"[ACTION] IP {ip} has been blocked")

        elif event == "LOGIN_SUCCESS":
            # successful login means it's probably a real user — give them a clean slate
            failed_attempts[ip] = 0
