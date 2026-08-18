package ctla;

import java.io.*;
import java.util.*;

public class ThreatDetector {

    private final List<LogEntry>       allLogs    = new ArrayList<>();
    private final PriorityQueue<LogEntry> threatQueue = new PriorityQueue<>();
    private final SuspiciousIPTracker  ipTracker  = new SuspiciousIPTracker();

    private volatile boolean monitoring = false;
    private Thread monitorThread;

    // Load logs from file — expects CSV: timestamp,ip,eventType,status
    public void loadFromFile(String filePath) throws IOException {
        allLogs.clear();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            boolean firstLine = true;
            while ((line = br.readLine()) != null) {
                if (firstLine) { firstLine = false; continue; } // skip header
                String[] parts = line.split(",", 4);
                if (parts.length < 4) continue;
                LogEntry entry = new LogEntry(
                    parts[0].trim(), parts[1].trim(), parts[2].trim(), parts[3].trim()
                );
                allLogs.add(entry);
                threatQueue.offer(entry);
                ipTracker.track(entry);
            }
        }
    }

    // Load sample/demo logs when no file is provided
    public void loadDemoLogs() {
        String[][] demo = {
            {"2024-01-15 08:23:11", "192.168.1.101", "FAILED_LOGIN",        "FAILURE"},
            {"2024-01-15 08:23:15", "192.168.1.101", "FAILED_LOGIN",        "FAILURE"},
            {"2024-01-15 08:23:18", "192.168.1.101", "FAILED_LOGIN",        "FAILURE"},
            {"2024-01-15 08:23:21", "192.168.1.101", "BRUTE_FORCE",         "DETECTED"},
            {"2024-01-15 08:23:22", "192.168.1.101", "UNAUTHORIZED_ACCESS", "BLOCKED"},
            {"2024-01-15 09:10:05", "10.0.0.55",     "MALWARE_DETECTED",    "QUARANTINED"},
            {"2024-01-15 09:45:33", "172.16.0.22",   "SUSPICIOUS_SCAN",     "WARNING"},
            {"2024-01-15 10:00:01", "10.0.0.55",     "MALWARE_DETECTED",    "QUARANTINED"},
            {"2024-01-15 10:12:44", "192.168.5.200", "FAILED_LOGIN",        "FAILURE"},
            {"2024-01-15 10:12:50", "192.168.5.200", "FAILED_LOGIN",        "FAILURE"},
            {"2024-01-15 10:12:55", "192.168.5.200", "FAILED_LOGIN",        "FAILURE"},
            {"2024-01-15 10:13:01", "192.168.5.200", "FAILED_LOGIN",        "FAILURE"},
            {"2024-01-15 10:13:05", "192.168.5.200", "FAILED_LOGIN",        "FAILURE"},
            {"2024-01-15 11:00:00", "192.168.1.10",  "NORMAL",              "SUCCESS"},
            {"2024-01-15 11:30:00", "172.16.0.22",   "SUSPICIOUS_SCAN",     "WARNING"},
        };

        for (String[] row : demo) {
            LogEntry e = new LogEntry(row[0], row[1], row[2], row[3]);
            allLogs.add(e);
            threatQueue.offer(e);
            ipTracker.track(e);
        }
    }

    // Add a single entry (from manual form)
    public void addEntry(LogEntry entry) {
        allLogs.add(entry);
        threatQueue.offer(entry);
        ipTracker.track(entry);
    }

    // Clear everything
    public void clearAll() {
        allLogs.clear();
        threatQueue.clear();
        stopMonitoring();
    }

    public List<LogEntry> getTopThreats(int n) {
        PriorityQueue<LogEntry> copy = new PriorityQueue<>(threatQueue);
        List<LogEntry> result = new ArrayList<>();
        for (int i = 0; i < n && !copy.isEmpty(); i++) {
            result.add(copy.poll());
        }
        return result;
    }

    public List<LogEntry> getAllLogs()   { return Collections.unmodifiableList(allLogs); }
    public SuspiciousIPTracker getIPTracker() { return ipTracker; }

    public long countBySeverity(String label) {
        return allLogs.stream()
            .filter(e -> e.getSeverityLabel().equals(label))
            .count();
    }

    public void saveReport(String outputPath) throws IOException {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(outputPath))) {
            bw.write("=== CYBER THREAT LOG ANALYZER — REPORT ===\n\n");
            bw.write("SUMMARY\n");
            bw.write("Total Logs   : " + allLogs.size() + "\n");
            bw.write("Critical     : " + countBySeverity("CRITICAL") + "\n");
            bw.write("High         : " + countBySeverity("HIGH")     + "\n");
            bw.write("Medium       : " + countBySeverity("MEDIUM")   + "\n");
            bw.write("Low          : " + countBySeverity("LOW")      + "\n\n");
            bw.write("TOP THREATS (Priority Ranked)\n");
            for (LogEntry e : getTopThreats(10)) {
                bw.write(e.toString() + "\n");
            }
            bw.write("\nSUSPICIOUS IPs\n");
            for (String ip : ipTracker.getTopSuspiciousIPs(10)) {
                bw.write(ip + "\n");
            }
        }
    }

    // Background monitoring thread — scans for new critical threats every 5s
    public void startMonitoring(Runnable onAlertCallback) {
        monitoring = true;
        monitorThread = new Thread(() -> {
            while (monitoring) {
                try {
                    Thread.sleep(5000);
                    long critical = countBySeverity("CRITICAL");
                    if (critical > 0) {
                        onAlertCallback.run();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }, "CTLA-Monitor");
        monitorThread.setDaemon(true);
        monitorThread.start();
    }

    public void stopMonitoring() {
        monitoring = false;
        if (monitorThread != null) monitorThread.interrupt();
    }
}
