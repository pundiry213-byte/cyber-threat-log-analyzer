package ctla;

import java.util.*;

public class SuspiciousIPTracker {

    private final HashMap<String, Integer> ipHitCount   = new HashMap<>();
    private final HashMap<String, Integer> ipThreatSum  = new HashMap<>();
    private static final int BRUTE_FORCE_THRESHOLD = 5;

    public void track(LogEntry entry) {
        String ip = entry.getIpAddress();
        ipHitCount.merge(ip, 1, Integer::sum);
        ipThreatSum.merge(ip, entry.getThreatScore(), Integer::sum);
    }

    public boolean isSuspicious(String ip) {
        return ipHitCount.getOrDefault(ip, 0) >= BRUTE_FORCE_THRESHOLD;
    }

    public List<String> getTopSuspiciousIPs(int limit) {
        return ipHitCount.entrySet().stream()
            .filter(e -> e.getValue() >= BRUTE_FORCE_THRESHOLD)
            .sorted((a, b) -> {
                int totalA = ipThreatSum.getOrDefault(a.getKey(), 0);
                int totalB = ipThreatSum.getOrDefault(b.getKey(), 0);
                return Integer.compare(totalB, totalA);
            })
            .limit(limit)
            .map(e -> e.getKey() + " (" + e.getValue() + " hits)")
            .toList();
    }

    public int getHitCount(String ip) {
        return ipHitCount.getOrDefault(ip, 0);
    }

    public Map<String, Integer> getAllIPHits() {
        return Collections.unmodifiableMap(ipHitCount);
    }
}
