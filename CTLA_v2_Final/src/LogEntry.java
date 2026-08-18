package ctla;

public class LogEntry implements Comparable<LogEntry> {

    public enum EventType {
        FAILED_LOGIN, MALWARE_DETECTED, UNAUTHORIZED_ACCESS,
        BRUTE_FORCE, SUSPICIOUS_SCAN, NORMAL
    }

    private String timestamp;
    private String ipAddress;
    private EventType eventType;
    private String status;
    private int threatScore;

    public LogEntry(String timestamp, String ipAddress, String eventType, String status) {
        this.timestamp  = timestamp;
        this.ipAddress  = ipAddress;
        this.eventType  = parseEventType(eventType);
        this.status     = status;
        this.threatScore = calculateScore();
    }

    private EventType parseEventType(String raw) {
        return switch (raw.trim().toUpperCase().replace(" ", "_")) {
            case "FAILED_LOGIN"        -> EventType.FAILED_LOGIN;
            case "MALWARE_DETECTED"    -> EventType.MALWARE_DETECTED;
            case "UNAUTHORIZED_ACCESS" -> EventType.UNAUTHORIZED_ACCESS;
            case "BRUTE_FORCE"         -> EventType.BRUTE_FORCE;
            case "SUSPICIOUS_SCAN"     -> EventType.SUSPICIOUS_SCAN;
            default                    -> EventType.NORMAL;
        };
    }

    private int calculateScore() {
        return switch (eventType) {
            case MALWARE_DETECTED    -> 95;
            case BRUTE_FORCE         -> 85;
            case UNAUTHORIZED_ACCESS -> 75;
            case SUSPICIOUS_SCAN     -> 60;
            case FAILED_LOGIN        -> 40;
            case NORMAL              -> 10;
        };
    }

    public String getSeverityLabel() {
        if (threatScore >= 80) return "CRITICAL";
        if (threatScore >= 60) return "HIGH";
        if (threatScore >= 40) return "MEDIUM";
        return "LOW";
    }

    @Override
    public int compareTo(LogEntry other) {
        return Integer.compare(other.threatScore, this.threatScore);
    }

    // Getters
    public String getTimestamp()  { return timestamp;   }
    public String getIpAddress()  { return ipAddress;   }
    public EventType getEventType() { return eventType; }
    public String getStatus()     { return status;      }
    public int getThreatScore()   { return threatScore; }

    @Override
    public String toString() {
        return String.format("[%s] %-20s %-22s %-10s Score:%-3d %s",
            timestamp, ipAddress, eventType, status, threatScore, getSeverityLabel());
    }
}
