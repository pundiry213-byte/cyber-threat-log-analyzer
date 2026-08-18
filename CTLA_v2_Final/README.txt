# Cyber Threat Log Analyzer (CTLA)

Cyber Threat Log Analyzer (CTLA) is a **Java-based desktop application** designed to analyze security logs and identify potentially suspicious cyber-security activity.

The project demonstrates how **Data Structures and Algorithms** can be applied to log analysis, threat prioritization, and suspicious IP detection.

## 🚀 Features

* Java Swing desktop dashboard
* Manual security log entry
* CSV log file loading
* Automatic threat scoring
* Threat severity classification
* Priority-based threat analysis
* Suspicious IP tracking
* Background monitoring
* Sample security log generation
* Threat report generation
* Clear and analyze log data through the GUI

## 🧠 DSA Concepts Used

### PriorityQueue

A `PriorityQueue` is used to prioritize security events based on their threat score.

High-severity threats can therefore be retrieved before lower-severity events.

### HashMap

A `HashMap` is used to track activity associated with IP addresses.

Repeated activity from the same IP can be identified and flagged as suspicious.

### ArrayList

`ArrayList` is used to store collections of log entries during analysis.

## 🔍 Threat Detection

The application assigns scores to different security events.

| Event Type          | Threat Score | Severity |
| ------------------- | -----------: | -------- |
| MALWARE_DETECTED    |           95 | CRITICAL |
| BRUTE_FORCE         |           85 | CRITICAL |
| UNAUTHORIZED_ACCESS |           75 | HIGH     |
| SUSPICIOUS_SCAN     |           60 | HIGH     |
| FAILED_LOGIN        |           40 | MEDIUM   |
| NORMAL              |           10 | LOW      |

These scores are used to prioritize threats during analysis.

## 📊 Application Workflow

```text id="f2u4k6"
Security Logs
     │
     ├── Manual Entry
     │
     └── CSV File
           │
           ▼
       Log Analysis
           │
           ▼
      Threat Scoring
           │
      ┌────┴────┐
      ▼         ▼
PriorityQueue  HashMap
      │         │
      ▼         ▼
Top Threats  Suspicious IPs
      │         │
      └────┬────┘
           ▼
      Threat Report
```

## 🖥️ Dashboard

The Java Swing dashboard provides information such as:

* Total number of logs
* Critical threats
* High-severity threats
* Suspicious IP addresses
* Security log table
* Top threats
* Threat analysis results
* Generated reports

## 📁 Project Structure

```text id="0p3ykn"
cyber-threat-log-analyzer/
│
├── src/
│   ├── CTLADashboard.java
│   ├── LogEntry.java
│   ├── LogGenerator.java
│   ├── SuspiciousIPTracker.java
│   └── ThreatDetector.java
│
├── logs/
│   ├── sample_logs.csv
│   └── generated_logs.csv
│
└── README.md
```

## 📄 CSV Format

Security logs can be loaded from CSV files.

Example:

```csv id="6wx6u3"
timestamp,ip,eventType,status
2024-01-15 08:23:11,192.168.1.101,FAILED_LOGIN,FAILURE
```

Supported event types include:

```text id="7d2x0q"
FAILED_LOGIN
MALWARE_DETECTED
UNAUTHORIZED_ACCESS
BRUTE_FORCE
SUSPICIOUS_SCAN
NORMAL
```

## ⚙️ Technologies Used

* Java
* Java Swing
* Data Structures & Algorithms
* PriorityQueue
* HashMap
* ArrayList
* File I/O
* CSV Processing
* Multithreading

## ▶️ How to Run

### Prerequisites

Install **Java JDK 8 or later**.

Check your installation:

```bash id="r1q7f5"
java -version
```

Check the compiler:

```bash id="6k8e2x"
javac -version
```

### Compile

From the project root:

```bash id="6p7u5e"
javac -d out src/*.java
```

### Run

```bash id="a5y0j9"
java -cp out ctla.CTLADashboard
```

## 🧪 Generate Sample Logs

The project contains a log generator for creating synthetic security events.

After compiling:

```bash id="j7v2pw"
java -cp out ctla.LogGenerator
```

The generated logs can then be loaded into the CTLA dashboard for analysis.

## 🔮 Future Improvements

* Real-time system log monitoring
* Network traffic integration
* Database-backed log storage
* Configurable threat scoring
* IP geolocation
* Advanced security visualizations
* Machine-learning based anomaly detection
* Automated email/notification alerts

## 🎯 Learning Outcomes

This project demonstrates practical use of:

* Priority Queues
* Hash Maps
* Array Lists
* File Processing
* Multithreading
* Object-Oriented Programming
* Algorithmic threat analysis

## 👥 Team

**Team Krantiveer**

---

> **Note:** CTLA is an academic cybersecurity project using synthetic/sample security logs. It is not intended to replace a production SIEM or intrusion detection system.
