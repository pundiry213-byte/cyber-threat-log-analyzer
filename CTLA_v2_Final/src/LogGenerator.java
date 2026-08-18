package ctla;

import java.io.*;
import java.time.*;
import java.time.format.*;
import java.util.*;

public class LogGenerator {

    private static final Random RAND = new Random();
    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final String[] EVENT_TYPES = {
        "FAILED_LOGIN", "FAILED_LOGIN", "FAILED_LOGIN",   // higher weight
        "MALWARE_DETECTED",
        "UNAUTHORIZED_ACCESS",
        "BRUTE_FORCE",
        "SUSPICIOUS_SCAN", "SUSPICIOUS_SCAN",
        "NORMAL", "NORMAL", "NORMAL"                       // most common
    };

    private static final Map<String, String> EVENT_STATUS = Map.of(
        "FAILED_LOGIN",        "FAILURE",
        "MALWARE_DETECTED",    "QUARANTINED",
        "UNAUTHORIZED_ACCESS", "BLOCKED",
        "BRUTE_FORCE",         "DETECTED",
        "SUSPICIOUS_SCAN",     "WARNING",
        "NORMAL",              "SUCCESS"
    );

    // Fixed attacker IPs — simulate repeated brute force
    private static final String[] ATTACKER_IPS = {
        "45.33.32.156", "192.168.1.101", "10.0.0.55",
        "172.16.0.99",  "203.0.113.42"
    };

    // Normal internal IPs
    private static final String[] NORMAL_IPS = {
        "192.168.1.10", "192.168.1.20", "192.168.1.30",
        "10.0.0.5",     "10.0.0.15",    "10.0.0.25",
        "172.16.0.5",   "172.16.0.10"
    };

    public static void generate(String outputPath, int totalLogs) throws IOException {
        LocalDateTime baseTime = LocalDateTime.of(2024, 1, 15, 0, 0, 0);

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(outputPath))) {
            bw.write("timestamp,ip,eventType,status\n");

            for (int i = 0; i < totalLogs; i++) {
                // Advance time randomly (1-300 seconds per entry)
                baseTime = baseTime.plusSeconds(RAND.nextInt(300) + 1);

                String ip        = pickIP();
                String eventType = pickEvent(ip);
                String status    = EVENT_STATUS.get(eventType);
                String timestamp = baseTime.format(FMT);

                bw.write(timestamp + "," + ip + "," + eventType + "," + status + "\n");
            }

            // Inject a realistic brute force burst at the end
            injectBruteForceBurst(bw, baseTime.plusMinutes(10));
        }

        System.out.println("✅ Generated " + (totalLogs + 20) + " logs → " + outputPath);
    }

    // Attacker IPs get malicious events, normal IPs get mostly NORMAL
    private static String pickEvent(String ip) {
        boolean isAttacker = Arrays.asList(ATTACKER_IPS).contains(ip);
        if (isAttacker) {
            String[] attackEvents = {
                "FAILED_LOGIN", "FAILED_LOGIN", "BRUTE_FORCE",
                "UNAUTHORIZED_ACCESS", "MALWARE_DETECTED", "SUSPICIOUS_SCAN"
            };
            return attackEvents[RAND.nextInt(attackEvents.length)];
        }
        return EVENT_TYPES[RAND.nextInt(EVENT_TYPES.length)];
    }

    private static String pickIP() {
        // 30% chance attacker IP, 70% normal
        if (RAND.nextInt(10) < 3) {
            return ATTACKER_IPS[RAND.nextInt(ATTACKER_IPS.length)];
        }
        // 10% chance totally random external IP
        if (RAND.nextInt(10) < 1) {
            return randomPublicIP();
        }
        return NORMAL_IPS[RAND.nextInt(NORMAL_IPS.length)];
    }

    private static String randomPublicIP() {
        return (RAND.nextInt(223) + 1) + "." +
               RAND.nextInt(256) + "." +
               RAND.nextInt(256) + "." +
               (RAND.nextInt(254) + 1);
    }

    // Simulate a brute force attack — same IP, rapid failed logins
    private static void injectBruteForceBurst(BufferedWriter bw, LocalDateTime start)
            throws IOException {
        String attackerIP = "45.33.32.156";
        LocalDateTime t = start;
        for (int i = 0; i < 15; i++) {
            t = t.plusSeconds(RAND.nextInt(5) + 1);
            bw.write(t.format(FMT) + "," + attackerIP + ",FAILED_LOGIN,FAILURE\n");
        }
        // Escalate to brute force
        t = t.plusSeconds(2);
        bw.write(t.format(FMT) + "," + attackerIP + ",BRUTE_FORCE,DETECTED\n");
        t = t.plusSeconds(1);
        bw.write(t.format(FMT) + "," + attackerIP + ",UNAUTHORIZED_ACCESS,BLOCKED\n");
        t = t.plusSeconds(3);
        bw.write(t.format(FMT) + "," + attackerIP + ",MALWARE_DETECTED,QUARANTINED\n");
    }

    // Run standalone to generate logs
    public static void main(String[] args) throws IOException {
        int count = 500; // default
        if (args.length > 0) {
            try { count = Integer.parseInt(args[0]); } catch (Exception ignored) {}
        }
        generate("generated_logs.csv", count);
    }
}
