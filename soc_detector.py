from collections import defaultdict

failed_attempts = defaultdict(int)  # tracks how many times each IP has failed to login
blocked_ips = set()                 # IPs we've already flagged and blocked
THRESHOLD = 3                       # block after this many failed attempts
alert_count = 0

print("=== Auth Log Monitor ===\n")

with open("auth_logs.txt", "r") as file:
    for line in file:
        parts = line.strip().split()

        # need at least 5 fields (timestamp x2, event, user, ip) — skip garbage lines
        if len(parts) < 5:
            print(f"  [SKIP]    {line.strip()}")
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
                print(f"  [WARN]    {ip} ({user}) — failed attempt {failed_attempts[ip]}/{THRESHOLD}")
            else:
                print(f"  [ALERT]   {ip} ({user}) — threshold reached! blocking now")
                alert_count += 1

                # append to alerts file so we have a persistent record
                with open("alerts.txt", "a") as f:
                    f.write(f"[ALERT] {ip} | {user} | {THRESHOLD} attempts | {timestamp}\n")

                # blacklist the IP so we stop processing its future log entries
                blocked_ips.add(ip)
                print(f"  [BLOCKED] {ip} — logged to alerts.txt")

        elif event == "LOGIN_SUCCESS":
            if failed_attempts[ip] > 0:
                # had some failures before — note the reset
                print(f"  [OK]      {ip} ({user}) — logged in, cleared {failed_attempts[ip]} failed attempt(s)")
            else:
                # clean login, no prior failures
                print(f"  [OK]      {ip} ({user}) — logged in")
            
            # successful login means it's probably a real user — give them a clean slate
            failed_attempts[ip] = 0

        else:
            # log any unrecognised event types we haven't accounted for
            print(f"  [UNKNOWN] {ip} ({user}) — unrecognised event '{event}' at {timestamp}")

print(f"\n=== Done: {alert_count} alert(s), {len(blocked_ips)} IP(s) blocked ===")
