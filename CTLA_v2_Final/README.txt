╔══════════════════════════════════════════════════════════╗
║         CYBER THREAT LOG ANALYZER (CTLA) v2.0           ║
║         Team: krantiveer  |  Java Project                ║
╚══════════════════════════════════════════════════════════╝

── HOW TO RUN (No compile needed — .class files included) ──

    java -cp out ctla.CTLADashboard

── USAGE ─────────────────────────────────────────────────

  MANUAL ENTRY (Left Panel):
  1. Enter IP Address
  2. Enter Timestamp (or leave blank — auto fills current time)
  3. Select Event Type from dropdown
  4. Select Status from dropdown
  5. Click "+ Add Entry" → entry appears in table instantly

  FILE UPLOAD:
  1. Click "Load CSV File" → select sample_logs.csv or generated_logs.csv
  2. All entries load into the table
  3. You can COMBINE — add manual entries + load file together

  ANALYZE:
  → Click "Analyze All" after adding entries
  → Right panel shows:
       - Top Threats (Priority Queue ranked)
       - Suspicious IPs (HashMap tracked, 5+ hits)
       - Full Report (complete analysis)

  SAVE:
  → Click "Save Report" → exports full .txt report

  CLEAR:
  → Click "Clear All" to reset everything

── CSV FORMAT ────────────────────────────────────────────

  timestamp,ip,eventType,status
  2024-01-15 08:23:11,192.168.1.101,FAILED_LOGIN,FAILURE

  Event Types: FAILED_LOGIN | MALWARE_DETECTED |
               UNAUTHORIZED_ACCESS | BRUTE_FORCE |
               SUSPICIOUS_SCAN | NORMAL

── THREAT SCORES ─────────────────────────────────────────

  MALWARE_DETECTED    → 95  (CRITICAL)
  BRUTE_FORCE         → 85  (CRITICAL)
  UNAUTHORIZED_ACCESS → 75  (HIGH)
  SUSPICIOUS_SCAN     → 60  (HIGH)
  FAILED_LOGIN        → 40  (MEDIUM)
  NORMAL              → 10  (LOW)

── TEAM ──────────────────────────────────────────────────

  Jatin Prakash    – 240211832  (Team Lead)
  Vansh Bora       – 24021869
  Bhupesh Singh    – 240211965
