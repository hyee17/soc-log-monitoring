from collections import defaultdict
from datetime import datetime, timedelta

failed_attempts = defaultdict(int)  # tracks how many times each IP has failed to login
blocked_ips = set()                 # IPs we've already flagged and blocked
THRESHOLD = 3                       # block after this many failed attempts
BLOCK_DURATION_MINUTES = 30
alert_count = 0

def is_blocked(ip, current_time):
    if ip not in blocked_ips:
        return False
    if current_time >= blocked_ips[ip]:
        # cooldown expired, clean it up
        del blocked_ips[ip]
        failed_attempts[ip] = 0
        return False
    return True

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
        current_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        event = parts[2]
        user = parts[3]
        ip = parts[4]

        if event == "LOGIN_FAILED":
            # only ignore failed attempts from blocked IPs
            if is_blocked(ip, current_time):
                unblock_at = blocked_ips[ip].strftime("%H:%M:%S")
                print(f"  [IGNORED] {ip} ({user}) — blocked until {unblock_at}")
                continue

            failed_attempts[ip] += 1
            remaining = THRESHOLD - failed_attempts[ip]

            # show a warning as they get closer to the threshold
            if remaining > 0:
                print(f"  [WARN]    {ip} ({user}) — failed attempt {failed_attempts[ip]}/{THRESHOLD}")
            else:
                unblock_time = current_time + timedelta(minutes=BLOCK_DURATION_MINUTES)
                blocked_ips[ip] = unblock_time
                alert_count += 1

                print(f"  [ALERT]   {ip} ({user}) — threshold reached! blocking for {BLOCK_DURATION_MINUTES} mins")
                print(f"  [BLOCKED] {ip} — unblocks at {unblock_time.strftime('%H:%M:%S')}, logged to alerts.txt")
                
                # append to alerts file so we have a persistent record
                with open("alerts.txt", "a") as f:
                    f.write(f"[ALERT] {ip} | {user} | {THRESHOLD} attempts | {timestamp} | blocked until {unblock_time}\n")

        elif event == "LOGIN_SUCCESS":
            if is_blocked(ip, current_time):
                unblock_at = blocked_ips[ip].strftime("%H:%M:%S")
                # block stands — successful login doesn't override it
                print(f"  [DENIED]  {ip} ({user}) — still blocked until {unblock_at}")
                continue
                
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

print(f"\n=== Done: {alert_count} alert(s), {len(blocked_ips)} IP(s) still blocked ===")
