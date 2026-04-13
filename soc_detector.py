from collections import defaultdict

failed_attempts = defaultdict(int)  # tracks how many times each IP has failed to login
blocked_ips = set()                 # IPs we've already flagged and blocked
THRESHOLD = 3                       # block after this many failed attempts

print("=" * 60)
print(" Auth Log Monitor Starting...")
print("=" * 60 + "\n")

with open("auth_logs.txt", "r") as file:
    for line in file:
        parts = line.strip().split()

        # need at least 5 fields (timestamp x2, event, user, ip) — skip garbage lines
        if len(parts) < 5:
            print(f"  [SKIP] Malformed line ignored: '{line.strip()}'")
            continue

        # pull out each field by position
        timestamp = parts[0] + " " + parts[1]
        event = parts[2]
        user = parts[3]
        ip = parts[4]

        # nothing more to do for already-blocked IPs
        if ip in blocked_ips:
            print(f"  [BLOCKED] Ignored activity from {ip} (user: {user}) at {timestamp}")
            continue

        if event == "LOGIN_FAILED":
            failed_attempts[ip] += 1
            remaining = THRESHOLD - failed_attempts[ip]

            # show a warning as they get closer to the threshold
            if remaining > 0:
                print(f"  [WARN] Failed login — user: {user}, IP: {ip}, attempt #{failed_attempts[ip]} ({remaining} more until block)")
            
            # only alert once — right when they hit the threshold, not on every attempt after
            if failed_attempts[ip] == THRESHOLD:
                print(f"\n{'!' * 60}")
                print(f"  [ALERT] Brute-force detected!")
                print(f"          User     : {user}")
                print(f"          IP       : {ip}")
                print(f"          Attempts : {failed_attempts[ip]}")
                print(f"          Time     : {timestamp}")
                print(f"{'!' * 60}\n")

                # save a clean, simple entry to the alert file
                alert_message = (
                    f"[ALERT] Possible brute-force attack detected!\n"
                    f"IP: {ip}\n"
                    f"Failed Attempts: {failed_attempts[ip]}\n"
                    f"Time: {timestamp}\n"
                    + "-" * 50
                )

                # append to alerts file so we have a persistent record
                with open("alerts.txt", "a") as alert_file:
                    alert_file.write(alert_message + "\n")

                # blacklist the IP so we stop processing its future log entries
                blocked_ips.add(ip)
                print(f"  [ACTION] IP {ip} has been blocked and logged to alerts.txt\n")

        elif event == "LOGIN_SUCCESS":
            if failed_attempts[ip] > 0:
                # had some failures before — note the reset
                print(f"  [OK] Successful login — user: {user}, IP: {ip} (resetting {failed_attempts[ip]} failed attempt(s))")
            else:
                # clean login, no prior failures
                print(f"  [OK] Successful login — user: {user}, IP: {ip}")
            
            # successful login means it's probably a real user — give them a clean slate
            failed_attempts[ip] = 0

        else:
            # log any unrecognised event types we haven't accounted for
            print(f"  [UNKNOWN] Unrecognised event '{event}' from {ip} at {timestamp}")

print("\n" + "=" * 60)
print(f"  Monitoring complete. Blocked IPs: {blocked_ips if blocked_ips else 'none'}")
print("=" * 60)
