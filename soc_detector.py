import json
from collections import defaultdict
from datetime import datetime, timedelta

failed_attempts = defaultdict(int)  # tracks how many times each IP has failed to login; defaults to 0 for new IPs
blocked_ips = {}                    # maps blocked IP -> datetime when the block expires
THRESHOLD = 3                       # number of failed attempts before an IP gets blocked
BLOCK_DURATION_MINUTES = 30         # how long a block lasts before the IP is allowed to try again
alert_count = 0                     # running total of how many IPs have been blocked this session

def is_blocked(ip, current_time):
    if ip not in blocked_ips:       # IP has never been blocked, allow it through
        return False
    if current_time >= blocked_ips[ip]:  # block duration has expired
        del blocked_ips[ip]              # remove from blocked list so it's treated as fresh
        failed_attempts[ip] = 0          # reset their failed attempt counter
        return False
    return True                     # block is still active, IP is restricted

def get_severity(attempts):
    if attempts == THRESHOLD:       # exactly hit the limit — highest severity
        return "HIGH"
    elif attempts == THRESHOLD - 1: # one attempt away from being blocked — warn early
        return "MEDIUM"
    else:                           # early stage, low risk
        return "LOW"

print("=== JSON Auth Log Monitor ===\n")

with open("auth_logs.json", "r") as file:
    logs = json.load(file)          # parse the entire JSON file into a list of log entries

    for entry in logs:              # process each log entry one by one
        required_fields = ["timestamp", "event", "user", "ip"]

        if not all(field in entry for field in required_fields):  # skip entries missing any required field
            print(f"[SKIP] Invalid log entry: {entry}")
            continue

        try:
            timestamp = entry["timestamp"]                                   # raw timestamp string from log
            current_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")# convert string to datetime object for comparisons
            event = entry["event"]                                           # e.g. LOGIN_FAILED, LOGIN_SUCCESS
            user = entry["user"]                                             # username attempting the login
            ip = entry["ip"]                                                 # source IP address of the attempt

        except Exception:                           # catches malformed timestamps or unexpected field types
            print(f"[SKIP] Invalid log entry: {entry}")
            continue                               # move on to the next entry without crashing

        if event == "LOGIN_FAILED":
            if is_blocked(ip, current_time):                                 # don't count failures from already-blocked IPs
                unblock_at = blocked_ips[ip].strftime("%H:%M:%S")
                print(f"  [IGNORED] {ip} ({user}) — blocked until {unblock_at}")
                continue

            failed_attempts[ip] += 1                                         # increment this IP's failure counter
            severity = get_severity(failed_attempts[ip])                     # determine severity based on current count

            if failed_attempts[ip] < THRESHOLD:                              # not yet at the limit — just warn
                print(f"  [{severity}] {ip} ({user}) — failed attempt {failed_attempts[ip]}/{THRESHOLD}")
            else:                                                             # hit or exceeded the threshold — block the IP
                unblock_time = current_time + timedelta(minutes=BLOCK_DURATION_MINUTES)  # calculate when block expires
                blocked_ips[ip] = unblock_time                               # register the block with its expiry time
                alert_count += 1                                             # increment global alert counter

                print(f"  [ALERT-{severity}] {ip} ({user}) — blocking for {BLOCK_DURATION_MINUTES} mins")
                print(f"  [BLOCKED] {ip} — until {unblock_time.strftime('%H:%M:%S')}")

                with open("alerts.txt", "a") as f:                          # open in append mode to preserve previous alerts
                    f.write(
                        f"[{severity}] {ip} | {user} | {failed_attempts[ip]} attempts | "
                        f"{timestamp} | blocked until {unblock_time}\n"     # write one alert record per line
                    )

        elif event == "LOGIN_SUCCESS":
            if is_blocked(ip, current_time):                                 # a blocked IP can't log in even with correct credentials
                unblock_at = blocked_ips[ip].strftime("%H:%M:%S")
                print(f"  [DENIED]  {ip} ({user}) — still blocked until {unblock_at}")
                continue                                                     # skip the success handling below

            if failed_attempts[ip] > 0:                                      # had prior failures but eventually succeeded
                print(f"  [OK]      {ip} ({user}) — cleared {failed_attempts[ip]} failed attempt(s)")
            else:                                                             # clean login with no prior failures
                print(f"  [OK]      {ip} ({user}) — logged in")

            failed_attempts[ip] = 0                                          # reset counter — legitimate user gets a clean slate

        else:
            print(f"  [UNKNOWN] {ip} ({user}) — unrecognised event '{event}'")  # log unexpected event types for review

print(f"\n=== Done: {alert_count} alert(s), {len(blocked_ips)} IP(s) still blocked ===")  # final summary after processing all entries
