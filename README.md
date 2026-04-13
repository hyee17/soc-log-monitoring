# 🔐 SOC Log Monitoring System

## 📌 Overview

This project simulates a **Security Operations Center (SOC) log monitoring system** designed to detect and respond to suspicious login activities such as brute-force attacks.

It processes authentication logs in **JSON format**, applies detection rules, and generates alerts with severity levels. The system also simulates **incident response actions** such as temporary IP blocking.

---

## 🎯 Features

* 📊 **JSON Log Parsing** – Processes structured authentication logs
* 🚨 **Brute-Force Detection** – Identifies repeated failed login attempts
* ⚠️ **Severity Levels** – Classifies alerts into **LOW, MEDIUM, HIGH**
* 🔒 **Time-Based IP Blocking** – Blocks malicious IPs for a defined duration
* 📁 **Alert Logging** – Stores alerts in `alerts.txt` for analysis
* 🛡️ **Invalid Log Handling** – Skips malformed or incomplete log entries
* 🔁 **Real-Time Simulation Output** – Displays SOC-style monitoring messages

---

## 🧠 Detection Logic

* Each failed login attempt increases a counter per IP
* When attempts reach a threshold:

  * **HIGH severity alert is triggered**
  * IP is blocked for a configurable time period
* Successful login resets failed attempt count (if not blocked)
* Blocked IPs are denied access until cooldown expires

---

## 🧰 Technologies Used

* **Python**
* Built-in libraries:

  * `json`
  * `datetime`
  * `collections`

---

## 📂 Project Structure

```
SOC-Log-Monitoring/
│── soc_detector.py
│── auth_logs.json
│── alerts.txt
│── README.md
│── screenshots/
```

---

## ▶️ How to Run

1. Clone the repository:

```
git clone https://github.com/hyee17/soc-log-monitoring.git
cd soc-log-monitoring
```

2. Run the script:

```
python soc_detector.py
```

3. View alerts:

* Output displayed in terminal
* Alerts saved in `alerts.txt`

---

## 📸 Screenshots

### 🖥️ 1. Normal Monitoring Output

Shows system processing logs with LOW/MEDIUM severity warnings.

```
[LOW] 192.168.1.10 (user1) — failed attempt 1/3
[MEDIUM] 192.168.1.10 (user1) — failed attempt 2/3
```

---

### 🚨 2. Brute-Force Detection Alert

System detects threshold breach and triggers HIGH severity alert.

```
[ALERT-HIGH] 192.168.1.10 (user1) — blocking for 30 mins
[BLOCKED] 192.168.1.10 — until 10:30:08
```

---

### 🔒 3. Blocked IP Behavior

Blocked IP attempts are ignored or denied.

```
[DENIED]  192.168.1.10 (user1) — still blocked until 10:30:08
[IGNORED] 192.168.1.10 (user1) — blocked until 10:30:08
```

---

### ✅ 4. Successful Login Handling

Successful login or normal activity processed without security issues.

```
[OK]      192.168.1.30 (bob) — cleared 2 failed attempt(s)
[OK]      192.168.1.40 (alice) — logged in 
```

---

### ⚠️ 5. Data Validation

Invalid or malformed log entries that are safely ignored by the system.

```
[SKIP] Invalid log entry: {'timestamp': '2026-04-10 14:00:00', 'event': 'LOGIN_FAILED'}
[SKIP] Invalid log entry: {'timestamp': '2026-04-10 14:00:01', 'event': 'BADLINE', 'raw': 'only four'} 
```

---

### ❓ 6. Unknown Event Handling

Unrecognized or unexpected event types detected in the log stream.

```
[UNKNOWN] 192.168.1.50 (root) — unrecognised event 'LOGOUT'
```

---

### 📁 7. Alert Log File (`alerts.txt`)

Persistent storage of detected incidents.

```
[HIGH] 192.168.1.10 | user1 | 3 attempts | 2026-04-10 10:00:08 | blocked until 2026-04-10 10:30:08
[HIGH] 192.168.1.20 | admin | 3 attempts | 2026-04-10 11:00:06 | blocked until 2026-04-10 11:30:06
[HIGH] 192.168.1.50 | root | 3 attempts | 2026-04-10 14:01:06 | blocked until 2026-04-10 14:31:06
```

---

## 🚀 Future Improvements

* Web-based dashboard using Flask
* Integration with real-time log streams
* Email/SMS alert notifications
* Advanced anomaly detection (machine learning)

---

## 🎓 Learning Outcomes

This project demonstrates:

* SOC monitoring workflow
* Log analysis and threat detection
* Basic incident response simulation
* Security-focused Python development

---

## 📌 Author

* Wong Hui Yee

---

## ⭐ Note

This is a **learning project** designed to simulate real-world SOC operations and improve practical cybersecurity skills.
