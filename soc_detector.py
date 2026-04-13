from collections import defaultdict

failed_attempts = defaultdict(int)
THRESHOLD = 3

with open("auth_logs.txt", "r") as file:
    for line in file:
        parts = line.strip().split()

        timestamp = parts[0] + " " + parts[1]
        event = parts[2]
        user = parts[3]
        ip = parts[4]

        if event == "LOGIN_FAILED":
            failed_attempts[ip] += 1

            if failed_attempts[ip] >= THRESHOLD:
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

        if event == "LOGIN_SUCCESS":
            failed_attempts[ip] = 0
