package ctla;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class CTLADashboard extends JFrame {

    // ── Colors ────────────────────────────────────────────────────────────────
    private static final Color BG_DARK    = new Color(13,  17,  23);
    private static final Color BG_CARD    = new Color(22,  27,  34);
    private static final Color BG_PANEL   = new Color(30,  37,  46);
    private static final Color ACCENT_RED = new Color(248, 81,  73);
    private static final Color ACCENT_YEL = new Color(255, 193, 7);
    private static final Color ACCENT_GRN = new Color(56,  211, 159);
    private static final Color ACCENT_BLU = new Color(79,  172, 254);
    private static final Color TEXT_PRI   = new Color(230, 237, 243);
    private static final Color TEXT_SEC   = new Color(139, 148, 158);
    private static final Color BORDER_CLR = new Color(48,  54,  61);

    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // ── Core ──────────────────────────────────────────────────────────────────
    private final ThreatDetector detector = new ThreatDetector();

    // ── Log Table ─────────────────────────────────────────────────────────────
    private DefaultTableModel tableModel;
    private JTable logTable;

    // ── Stat Cards ────────────────────────────────────────────────────────────
    private JLabel lblTotal, lblCritical, lblHigh, lblSuspiciousIPs;

    // ── Form Fields ───────────────────────────────────────────────────────────
    private JTextField fldIP, fldTimestamp;
    private JComboBox<String> cmbEvent, cmbStatus;

    // ── Right Panel ───────────────────────────────────────────────────────────
    private JTextArea topThreatsArea;
    private JTextArea suspiciousIPArea;
    private JTextArea fullReportArea;

    // ── Status ────────────────────────────────────────────────────────────────
    private JLabel statusBar;

    // ─────────────────────────────────────────────────────────────────────────
    public CTLADashboard() {
        setTitle("Cyber Threat Log Analyzer  ·  CTLA v1.0  |  Team krantiveer");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1400, 860);
        setLocationRelativeTo(null);
        getContentPane().setBackground(BG_DARK);
        setLayout(new BorderLayout(0, 0));

        add(buildHeader(),    BorderLayout.NORTH);
        add(buildCenter(),    BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);

        setVisible(true);
        setStatus("Ready — Add log entries manually or load a CSV file, then click Analyze.");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // HEADER
    // ══════════════════════════════════════════════════════════════════════════
    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(BG_CARD);
        header.setBorder(new MatteBorder(0, 0, 1, 0, BORDER_CLR));
        header.setPreferredSize(new Dimension(0, 58));

        JLabel title = new JLabel("  ⚡ CYBER THREAT LOG ANALYZER");
        title.setFont(new Font("Monospaced", Font.BOLD, 17));
        title.setForeground(ACCENT_RED);

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        btns.setBackground(BG_CARD);
        btns.add(ctaButton("📂 Load CSV File",  ACCENT_BLU, e -> loadFile()));
        btns.add(ctaButton("📊 Analyze All",    ACCENT_GRN, e -> analyzeAndReport()));
        btns.add(ctaButton("💾 Save Report",    ACCENT_YEL, e -> saveReport()));
        btns.add(ctaButton("🗑 Clear All",      ACCENT_RED, e -> clearAll()));

        header.add(title, BorderLayout.WEST);
        header.add(btns,  BorderLayout.EAST);
        return header;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // CENTER — 3 columns: Form | Log Table | Report Panel
    // ══════════════════════════════════════════════════════════════════════════
    private JPanel buildCenter() {
        JPanel center = new JPanel(new BorderLayout(10, 10));
        center.setBackground(BG_DARK);
        center.setBorder(new EmptyBorder(10, 12, 6, 12));

        center.add(buildStatsRow(),   BorderLayout.NORTH);

        JPanel mainRow = new JPanel(new BorderLayout(10, 0));
        mainRow.setBackground(BG_DARK);
        mainRow.add(buildEntryForm(),  BorderLayout.WEST);
        mainRow.add(buildLogTable(),   BorderLayout.CENTER);
        mainRow.add(buildReportPanel(),BorderLayout.EAST);

        center.add(mainRow, BorderLayout.CENTER);
        return center;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // STAT CARDS
    // ══════════════════════════════════════════════════════════════════════════
    private JPanel buildStatsRow() {
        JPanel row = new JPanel(new GridLayout(1, 4, 10, 0));
        row.setBackground(BG_DARK);
        row.setPreferredSize(new Dimension(0, 82));

        lblTotal         = new JLabel("0", SwingConstants.CENTER);
        lblCritical      = new JLabel("0", SwingConstants.CENTER);
        lblHigh          = new JLabel("0", SwingConstants.CENTER);
        lblSuspiciousIPs = new JLabel("0", SwingConstants.CENTER);

        row.add(statCard("Total Logs",     lblTotal,         ACCENT_BLU));
        row.add(statCard("Critical",       lblCritical,      ACCENT_RED));
        row.add(statCard("High",           lblHigh,          ACCENT_YEL));
        row.add(statCard("Suspicious IPs", lblSuspiciousIPs, new Color(180, 80, 255)));
        return row;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MANUAL ENTRY FORM (Left column)
    // ══════════════════════════════════════════════════════════════════════════
    private JPanel buildEntryForm() {
        JPanel outer = buildCard("✏️  Add Log Entry Manually");
        outer.setPreferredSize(new Dimension(270, 0));

        JPanel form = new JPanel(new GridBagLayout());
        form.setBackground(BG_CARD);
        form.setBorder(new EmptyBorder(12, 12, 12, 12));
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(5, 4, 5, 4);
        gc.fill   = GridBagConstraints.HORIZONTAL;
        gc.anchor = GridBagConstraints.WEST;

        // IP Address
        gc.gridx = 0; gc.gridy = 0; gc.weightx = 0;
        form.add(formLabel("IP Address"), gc);
        gc.gridx = 0; gc.gridy = 1; gc.weightx = 1;
        fldIP = formField("e.g. 192.168.1.101");
        form.add(fldIP, gc);

        // Timestamp
        gc.gridx = 0; gc.gridy = 2; gc.weightx = 0;
        form.add(formLabel("Timestamp"), gc);
        gc.gridx = 0; gc.gridy = 3; gc.weightx = 1;
        fldTimestamp = formField("auto-filled if empty");
        form.add(fldTimestamp, gc);

        // Event Type
        gc.gridx = 0; gc.gridy = 4; gc.weightx = 0;
        form.add(formLabel("Event Type"), gc);
        gc.gridx = 0; gc.gridy = 5; gc.weightx = 1;
        cmbEvent = new JComboBox<>(new String[]{
            "FAILED_LOGIN", "MALWARE_DETECTED", "UNAUTHORIZED_ACCESS",
            "BRUTE_FORCE", "SUSPICIOUS_SCAN", "NORMAL"
        });
        styleCombo(cmbEvent);
        form.add(cmbEvent, gc);

        // Status
        gc.gridx = 0; gc.gridy = 6; gc.weightx = 0;
        form.add(formLabel("Status"), gc);
        gc.gridx = 0; gc.gridy = 7; gc.weightx = 1;
        cmbStatus = new JComboBox<>(new String[]{
            "FAILURE", "QUARANTINED", "BLOCKED", "DETECTED", "WARNING", "SUCCESS"
        });
        styleCombo(cmbStatus);
        form.add(cmbStatus, gc);

        // Add Entry Button
        gc.gridx = 0; gc.gridy = 8; gc.weightx = 1;
        gc.insets = new Insets(16, 4, 4, 4);
        JButton btnAdd = ctaButton("＋ Add Entry", ACCENT_GRN, e -> addManualEntry());
        btnAdd.setPreferredSize(new Dimension(0, 36));
        form.add(btnAdd, gc);

        // Hint box
        gc.gridy = 9;
        gc.insets = new Insets(16, 4, 4, 4);
        JTextArea hint = new JTextArea(
            "Tip:\nAdd multiple entries,\nthen click 'Analyze All'\nto generate the full\nthreat report."
        );
        hint.setEditable(false);
        hint.setBackground(BG_PANEL);
        hint.setForeground(TEXT_SEC);
        hint.setFont(new Font("SansSerif", Font.ITALIC, 11));
        hint.setBorder(new EmptyBorder(8, 8, 8, 8));
        form.add(hint, gc);

        outer.add(form, BorderLayout.CENTER);
        return outer;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // LOG TABLE (Center column)
    // ══════════════════════════════════════════════════════════════════════════
    private JPanel buildLogTable() {
        JPanel wrapper = buildCard("📋  Log Entries");

        String[] cols = {"Timestamp", "IP Address", "Event Type", "Status", "Score", "Severity"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        logTable = new JTable(tableModel);
        logTable.setBackground(BG_CARD);
        logTable.setForeground(TEXT_PRI);
        logTable.setGridColor(BORDER_CLR);
        logTable.setRowHeight(27);
        logTable.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logTable.setSelectionBackground(BG_PANEL);
        logTable.setSelectionForeground(ACCENT_BLU);
        logTable.setShowVerticalLines(false);
        logTable.setIntercellSpacing(new Dimension(0, 1));

        JTableHeader th = logTable.getTableHeader();
        th.setBackground(BG_PANEL);
        th.setForeground(TEXT_SEC);
        th.setFont(new Font("SansSerif", Font.BOLD, 11));
        th.setBorder(new MatteBorder(0, 0, 1, 0, BORDER_CLR));

        int[] widths = {145, 125, 155, 90, 55, 80};
        for (int i = 0; i < widths.length; i++)
            logTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);

        // Severity column color
        logTable.getColumnModel().getColumn(5).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable t, Object v, boolean sel, boolean foc, int r, int c) {
                super.getTableCellRendererComponent(t, v, sel, foc, r, c);
                setHorizontalAlignment(CENTER);
                setBackground(BG_CARD);
                String val = v == null ? "" : v.toString();
                setForeground(switch (val) {
                    case "CRITICAL" -> ACCENT_RED;
                    case "HIGH"     -> ACCENT_YEL;
                    case "MEDIUM"   -> new Color(255, 140, 0);
                    default         -> ACCENT_GRN;
                });
                setFont(getFont().deriveFont(Font.BOLD));
                return this;
            }
        });

        // Score column center
        logTable.getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable t, Object v, boolean sel, boolean foc, int r, int c) {
                super.getTableCellRendererComponent(t, v, sel, foc, r, c);
                setHorizontalAlignment(CENTER);
                setBackground(BG_CARD);
                setForeground(TEXT_PRI);
                return this;
            }
        });

        JScrollPane sp = new JScrollPane(logTable);
        sp.getViewport().setBackground(BG_CARD);
        sp.setBorder(null);
        wrapper.add(sp, BorderLayout.CENTER);
        return wrapper;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // REPORT PANEL (Right column)
    // ══════════════════════════════════════════════════════════════════════════
    private JPanel buildReportPanel() {
        JPanel outer = new JPanel(new BorderLayout(0, 10));
        outer.setBackground(BG_DARK);
        outer.setPreferredSize(new Dimension(300, 0));

        // Top Threats
        JPanel topCard = buildCard("🔥 Top Threats");
        topCard.setPreferredSize(new Dimension(0, 220));
        topThreatsArea = reportArea(ACCENT_GRN);
        JScrollPane sp1 = plainScroll(topThreatsArea);
        topCard.add(sp1, BorderLayout.CENTER);

        // Suspicious IPs
        JPanel ipCard = buildCard("🚨 Suspicious IPs");
        ipCard.setPreferredSize(new Dimension(0, 180));
        suspiciousIPArea = reportArea(ACCENT_YEL);
        JScrollPane sp2 = plainScroll(suspiciousIPArea);
        ipCard.add(sp2, BorderLayout.CENTER);

        // Full Report
        JPanel reportCard = buildCard("📄 Full Threat Report");
        fullReportArea = reportArea(TEXT_PRI);
        fullReportArea.setFont(new Font("Monospaced", Font.PLAIN, 10));
        JScrollPane sp3 = plainScroll(fullReportArea);
        reportCard.add(sp3, BorderLayout.CENTER);

        JSplitPane split1 = new JSplitPane(JSplitPane.VERTICAL_SPLIT, ipCard, reportCard);
        split1.setDividerSize(4);
        split1.setDividerLocation(180);
        split1.setBorder(null);
        split1.setBackground(BG_DARK);

        JSplitPane split2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topCard, split1);
        split2.setDividerSize(4);
        split2.setDividerLocation(220);
        split2.setBorder(null);
        split2.setBackground(BG_DARK);

        outer.add(split2, BorderLayout.CENTER);
        return outer;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // STATUS BAR
    // ══════════════════════════════════════════════════════════════════════════
    private JPanel buildStatusBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 14, 4));
        bar.setBackground(BG_CARD);
        bar.setBorder(new MatteBorder(1, 0, 0, 0, BORDER_CLR));
        statusBar = new JLabel("● Initializing...");
        statusBar.setFont(new Font("Monospaced", Font.PLAIN, 11));
        statusBar.setForeground(TEXT_SEC);
        bar.add(statusBar);
        return bar;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // ACTIONS
    // ══════════════════════════════════════════════════════════════════════════

    private void addManualEntry() {
        String ip = fldIP.getText().trim();
        if (ip.isEmpty()) {
            JOptionPane.showMessageDialog(this, "IP Address cannot be empty.", "Validation", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String timestamp = fldTimestamp.getText().trim();
        if (timestamp.isEmpty()) {
            timestamp = LocalDateTime.now().format(FMT);
        }

        String event  = (String) cmbEvent.getSelectedItem();
        String status = (String) cmbStatus.getSelectedItem();

        LogEntry entry = new LogEntry(timestamp, ip, event, status);
        detector.addEntry(entry);

        tableModel.addRow(new Object[]{
            entry.getTimestamp(), entry.getIpAddress(),
            entry.getEventType(), entry.getStatus(),
            entry.getThreatScore(), entry.getSeverityLabel()
        });

        updateStatCards();
        fldIP.setText("");
        fldTimestamp.setText("");
        setStatus("Entry added — IP: " + ip + "  |  Event: " + event + "  |  Score: " + entry.getThreatScore());
    }

    private void loadFile() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Select Log CSV File");
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = fc.getSelectedFile();
            try {
                int before = detector.getAllLogs().size();
                detector.loadFromFile(f.getAbsolutePath());
                int added = detector.getAllLogs().size() - before;

                // Refresh table with all logs
                refreshTable();
                updateStatCards();
                setStatus("Loaded " + added + " entries from: " + f.getName() + "  |  Total: " + detector.getAllLogs().size());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                    "Error reading file:\n" + ex.getMessage(),
                    "Load Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void analyzeAndReport() {
        List<LogEntry> logs = detector.getAllLogs();
        if (logs.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "No log entries found.\nAdd entries manually or load a CSV file first.",
                "Nothing to Analyze", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        updateStatCards();

        // Top Threats
        StringBuilder top = new StringBuilder();
        List<LogEntry> threats = detector.getTopThreats(10);
        for (int i = 0; i < threats.size(); i++) {
            LogEntry e = threats.get(i);
            top.append(String.format("#%-2d [%3d] %-18s %s%n",
                i + 1, e.getThreatScore(), e.getIpAddress(), e.getEventType()));
        }
        topThreatsArea.setText(top.toString());

        // Suspicious IPs
        List<String> ips = detector.getIPTracker().getTopSuspiciousIPs(10);
        suspiciousIPArea.setText(ips.isEmpty()
            ? "No suspicious IPs detected.\n(Need 5+ hits from same IP)"
            : String.join("\n", ips));

        // Full Report
        fullReportArea.setText(buildFullReport(logs));

        setStatus("✅ Analysis complete — " + logs.size() + " entries processed.  "
            + "Critical: " + detector.countBySeverity("CRITICAL")
            + "  High: " + detector.countBySeverity("HIGH"));

        detector.startMonitoring(() -> SwingUtilities.invokeLater(
            () -> setStatus("⚠️ ALERT: Critical threats detected in background monitor!")));
    }

    private String buildFullReport(List<LogEntry> logs) {
        StringBuilder sb = new StringBuilder();
        sb.append("══════════════════════════════════════\n");
        sb.append("   CYBER THREAT LOG ANALYZER — REPORT\n");
        sb.append("   Team krantiveer  |  CTLA v1.0\n");
        sb.append("══════════════════════════════════════\n\n");

        sb.append("SUMMARY\n");
        sb.append("───────────────────────────────────\n");
        sb.append(String.format("  Total Logs    : %d%n", logs.size()));
        sb.append(String.format("  Critical      : %d%n", detector.countBySeverity("CRITICAL")));
        sb.append(String.format("  High          : %d%n", detector.countBySeverity("HIGH")));
        sb.append(String.format("  Medium        : %d%n", detector.countBySeverity("MEDIUM")));
        sb.append(String.format("  Low           : %d%n", detector.countBySeverity("LOW")));
        sb.append(String.format("  Suspicious IPs: %d%n",
            detector.getIPTracker().getTopSuspiciousIPs(100).size()));

        sb.append("\nTOP THREATS (Priority Ranked)\n");
        sb.append("───────────────────────────────────\n");
        for (LogEntry e : detector.getTopThreats(10)) {
            sb.append(String.format("  [%3d] %-16s %-22s %s%n",
                e.getThreatScore(), e.getIpAddress(), e.getEventType(), e.getSeverityLabel()));
        }

        sb.append("\nSUSPICIOUS IPs (5+ hits)\n");
        sb.append("───────────────────────────────────\n");
        List<String> ips = detector.getIPTracker().getTopSuspiciousIPs(10);
        if (ips.isEmpty()) sb.append("  None detected.\n");
        else ips.forEach(ip -> sb.append("  ").append(ip).append("\n"));

        sb.append("\nALL LOG ENTRIES\n");
        sb.append("───────────────────────────────────\n");
        for (LogEntry e : logs) {
            sb.append(String.format("  %s  %-16s  %-22s  %-12s  Score:%-3d  %s%n",
                e.getTimestamp(), e.getIpAddress(), e.getEventType(),
                e.getStatus(), e.getThreatScore(), e.getSeverityLabel()));
        }

        return sb.toString();
    }

    private void saveReport() {
        if (detector.getAllLogs().isEmpty()) {
            JOptionPane.showMessageDialog(this, "Nothing to save. Add entries first.", "Empty", JOptionPane.WARNING_MESSAGE);
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("CTLA_Report.txt"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                detector.saveReport(fc.getSelectedFile().getAbsolutePath());
                setStatus("✅ Report saved: " + fc.getSelectedFile().getName());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error:\n" + ex.getMessage(), "Save Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void clearAll() {
        int confirm = JOptionPane.showConfirmDialog(this,
            "Clear all log entries?", "Confirm Clear", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            detector.clearAll();
            tableModel.setRowCount(0);
            topThreatsArea.setText("");
            suspiciousIPArea.setText("");
            fullReportArea.setText("");
            lblTotal.setText("0"); lblCritical.setText("0");
            lblHigh.setText("0");  lblSuspiciousIPs.setText("0");
            setStatus("Cleared — ready for new entries.");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // HELPERS
    // ══════════════════════════════════════════════════════════════════════════

    private void refreshTable() {
        tableModel.setRowCount(0);
        for (LogEntry e : detector.getAllLogs()) {
            tableModel.addRow(new Object[]{
                e.getTimestamp(), e.getIpAddress(),
                e.getEventType(), e.getStatus(),
                e.getThreatScore(), e.getSeverityLabel()
            });
        }
    }

    private void updateStatCards() {
        lblTotal.setText(String.valueOf(detector.getAllLogs().size()));
        lblCritical.setText(String.valueOf(detector.countBySeverity("CRITICAL")));
        lblHigh.setText(String.valueOf(detector.countBySeverity("HIGH")));
        lblSuspiciousIPs.setText(String.valueOf(
            detector.getIPTracker().getTopSuspiciousIPs(100).size()));
    }

    private void setStatus(String msg) {
        statusBar.setText("● " + msg);
    }

    private JPanel statCard(String title, JLabel valueLabel, Color accent) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBackground(BG_CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_CLR),
            new EmptyBorder(8, 14, 8, 14)
        ));
        JLabel lbl = new JLabel(title);
        lbl.setFont(new Font("SansSerif", Font.PLAIN, 11));
        lbl.setForeground(TEXT_SEC);
        valueLabel.setFont(new Font("SansSerif", Font.BOLD, 28));
        valueLabel.setForeground(accent);
        card.add(lbl, BorderLayout.NORTH);
        card.add(valueLabel, BorderLayout.CENTER);
        return card;
    }

    private JPanel buildCard(String titleText) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBackground(BG_CARD);
        card.setBorder(BorderFactory.createLineBorder(BORDER_CLR));
        JLabel title = new JLabel("  " + titleText);
        title.setFont(new Font("SansSerif", Font.BOLD, 12));
        title.setForeground(TEXT_SEC);
        title.setPreferredSize(new Dimension(0, 30));
        title.setBorder(new MatteBorder(0, 0, 1, 0, BORDER_CLR));
        card.add(title, BorderLayout.NORTH);
        return card;
    }

    private JButton ctaButton(String text, Color color, ActionListener action) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("SansSerif", Font.BOLD, 12));
        btn.setForeground(color);
        btn.setBackground(BG_PANEL);
        btn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(color, 1),
            new EmptyBorder(4, 12, 4, 12)
        ));
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.addActionListener(action);
        btn.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e) {
                btn.setBackground(new Color(color.getRed(), color.getGreen(), color.getBlue(), 40));
            }
            public void mouseExited(MouseEvent e) { btn.setBackground(BG_PANEL); }
        });
        return btn;
    }

    private JLabel formLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(new Font("SansSerif", Font.BOLD, 11));
        l.setForeground(TEXT_SEC);
        return l;
    }

    private JTextField formField(String placeholder) {
        JTextField tf = new JTextField();
        tf.setBackground(BG_PANEL);
        tf.setForeground(TEXT_PRI);
        tf.setCaretColor(TEXT_PRI);
        tf.setFont(new Font("Monospaced", Font.PLAIN, 12));
        tf.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_CLR),
            new EmptyBorder(4, 8, 4, 8)
        ));
        tf.setToolTipText(placeholder);
        return tf;
    }

    private void styleCombo(JComboBox<String> cmb) {
        cmb.setBackground(BG_PANEL);
        cmb.setForeground(TEXT_PRI);
        cmb.setFont(new Font("Monospaced", Font.PLAIN, 12));
        cmb.setBorder(BorderFactory.createLineBorder(BORDER_CLR));
    }

    private JTextArea reportArea(Color fg) {
        JTextArea ta = new JTextArea();
        ta.setEditable(false);
        ta.setBackground(BG_CARD);
        ta.setForeground(fg);
        ta.setFont(new Font("Monospaced", Font.PLAIN, 11));
        ta.setBorder(new EmptyBorder(8, 8, 8, 8));
        return ta;
    }

    private JScrollPane plainScroll(JTextArea ta) {
        JScrollPane sp = new JScrollPane(ta);
        sp.setBorder(null);
        sp.getViewport().setBackground(BG_CARD);
        return sp;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MAIN
    // ══════════════════════════════════════════════════════════════════════════
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception ignored) {}
        SwingUtilities.invokeLater(CTLADashboard::new);
    }
}
