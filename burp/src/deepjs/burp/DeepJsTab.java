package deepjs.burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;

/**
 * The "DeepJS" tab. Pure Swing — it knows nothing about Burp and talks to the
 * extension through {@link Actions}, so it can be constructed and exercised
 * outside Burp.
 */
final class DeepJsTab extends JPanel {

    /** What the tab can ask the extension to do. */
    interface Actions {
        void sendToRepeater(List<String[]> endpointRows);

        void fetchHiddenNow();

        void analyseProxyHistory();

        void clearAll();

        void restartWorker(String commandLine);

        void settingsChanged();
    }

    /** A table whose rows are keyed, so a row can be updated in place when the worker learns more. */
    static final class KeyedModel extends AbstractTableModel {
        private final String[] columns;
        private final Map<String, String[]> rows = new LinkedHashMap<>();
        private final List<String> order = new ArrayList<>();

        KeyedModel(String... columns) {
            this.columns = columns;
        }

        void upsert(String key, String[] row) {
            boolean isNew = !rows.containsKey(key);
            rows.put(key, row);
            if (isNew) {
                order.add(key);
                fireTableRowsInserted(order.size() - 1, order.size() - 1);
            } else {
                int i = order.indexOf(key);
                fireTableRowsUpdated(i, i);
            }
        }

        void remove(String key) {
            int i = order.indexOf(key);
            if (i >= 0) {
                order.remove(i);
                rows.remove(key);
                fireTableRowsDeleted(i, i);
            }
        }

        String[] row(int modelIndex) {
            return rows.get(order.get(modelIndex));
        }

        void clear() {
            rows.clear();
            order.clear();
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return order.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int c) {
            return columns[c];
        }

        @Override
        public Object getValueAt(int r, int c) {
            String[] row = rows.get(order.get(r));
            return c < row.length ? row[c] : "";
        }
    }

    // Endpoint row layout — also what Actions.sendToRepeater receives.
    static final int E_METHOD = 0, E_URL = 1, E_QUERY = 2, E_BODY = 3, E_HEADERS = 4, E_KIND = 5, E_SOURCE = 6;

    final KeyedModel endpoints = new KeyedModel("Method", "URL", "Query", "Body", "Headers", "Found as", "Source");
    final KeyedModel secrets = new KeyedModel("Severity", "Type", "Value", "Key", "Source", "Note");
    final KeyedModel scripts = new KeyedModel("Script / source map", "Kind", "Status");
    final KeyedModel hosts = new KeyedModel("Host", "Class", "Service", "Non-production");

    final JCheckBox enabled = new JCheckBox("Analyse responses", true);
    final JCheckBox scopeOnly = new JCheckBox("In-scope only", false);
    final JCheckBox fetchHidden = new JCheckBox("Fetch hidden scripts", true);
    final JCheckBox fetchMaps = new JCheckBox("Fetch source maps", true);
    final JCheckBox raiseIssues = new JCheckBox("Report secrets as issues", true);
    final JCheckBox showStrings = new JCheckBox("Show string-only paths", true);
    final JTextField command = new JTextField(38);

    private final JLabel status = new JLabel("starting…");
    private final JTextArea other = new JTextArea();
    private final JTextArea log = new JTextArea();
    private final JTabbedPane tabs = new JTabbedPane();
    private final JTextField filter = new JTextField(22);
    private final JTable endpointTable = new JTable(endpoints);
    private final TableRowSorter<KeyedModel> endpointSorter = new TableRowSorter<>(endpoints);
    private final Map<String, List<String>> otherItems = new LinkedHashMap<>();
    private final Actions actions;

    DeepJsTab(Actions actions) {
        super(new BorderLayout(0, 4));
        this.actions = actions;
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        add(toolbar(), BorderLayout.NORTH);
        add(tabs, BorderLayout.CENTER);

        tabs.addTab("API calls", endpointPanel());
        tabs.addTab("Secrets", tablePanel(secrets, new int[]{70, 190, 200, 120, 260, 420}, true));
        tabs.addTab("Hidden scripts", scriptsPanel());
        tabs.addTab("Hosts", tablePanel(hosts, new int[]{320, 110, 110, 110}, false));
        tabs.addTab("Routes · GraphQL · packages", textPanel(other));
        tabs.addTab("Log / settings", settingsPanel());

        for (KeyedModel m : new KeyedModel[]{endpoints, secrets, scripts, hosts}) {
            m.addTableModelListener(e -> refreshTitles());
        }
        refreshTitles();
    }

    // ── layout ───────────────────────────────────────────────────────────────

    private JPanel toolbar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        for (JCheckBox box : new JCheckBox[]{enabled, scopeOnly, fetchHidden, fetchMaps, raiseIssues}) {
            box.addActionListener(e -> actions.settingsChanged());
            bar.add(box);
        }
        enabled.setToolTipText("Analyse every JavaScript / HTML response that passes through Burp");
        scopeOnly.setToolTipText("Ignore responses and never fetch anything outside the target scope");
        fetchHidden.setToolTipText("Request, through Burp, the chunks the bundler names but no page has loaded yet");
        fetchMaps.setToolTipText("Request source maps for analysed scripts and analyse the original sources");
        raiseIssues.setToolTipText("Add an issue to the site map for each non-public secret (shown by Burp Professional)");
        bar.add(Box.createHorizontalStrut(10));
        bar.add(button("Analyse proxy history", e -> actions.analyseProxyHistory()));
        bar.add(button("Clear", e -> actions.clearAll()));
        bar.add(Box.createHorizontalStrut(10));
        bar.add(status);
        return bar;
    }

    private static JButton button(String text, java.awt.event.ActionListener l) {
        JButton b = new JButton(text);
        b.addActionListener(l);
        return b;
    }

    private JPanel endpointPanel() {
        endpointTable.setRowSorter(endpointSorter);
        endpointTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        endpointTable.setAutoCreateColumnsFromModel(false);
        widths(endpointTable, new int[]{70, 520, 160, 180, 150, 80, 320});
        endpointTable.getColumnModel().getColumn(E_METHOD).setCellRenderer(new MethodRenderer());

        filter.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyFilter(); }
            public void removeUpdate(DocumentEvent e) { applyFilter(); }
            public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        showStrings.addActionListener(e -> applyFilter());
        showStrings.setToolTipText("Paths that appear as strings but were not seen at a recognised call site");

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        top.add(new JLabel("Filter:"));
        top.add(filter);
        top.add(showStrings);
        top.add(button("Send to Repeater", e -> actions.sendToRepeater(selectedEndpoints())));
        top.add(button("Copy URLs", e -> copy(selectedEndpoints(), E_URL)));

        JPopupMenu menu = new JPopupMenu();
        JMenuItem toRepeater = new JMenuItem("Send to Repeater");
        toRepeater.addActionListener(e -> actions.sendToRepeater(selectedEndpoints()));
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> copy(selectedEndpoints(), E_URL));
        menu.add(toRepeater);
        menu.add(copyUrl);
        endpointTable.setComponentPopupMenu(menu);

        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(endpointTable), BorderLayout.CENTER);
        return p;
    }

    private JPanel scriptsPanel() {
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        top.add(new JLabel("Scripts and source maps the analysed code refers to — the parts of the app no page has loaded."));
        top.add(button("Fetch now", e -> actions.fetchHiddenNow()));
        JPanel p = tablePanel(scripts, new int[]{760, 110, 180}, false);
        p.add(top, BorderLayout.NORTH);
        return p;
    }

    private JPanel tablePanel(KeyedModel model, int[] columnWidths, boolean severityColours) {
        JTable t = new JTable(model);
        t.setAutoCreateRowSorter(true);
        widths(t, columnWidths);
        if (severityColours) {
            t.getColumnModel().getColumn(0).setCellRenderer(new SeverityRenderer());
        }
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copyCell = new JMenuItem("Copy cell");
        copyCell.addActionListener(e -> {
            int r = t.getSelectedRow(), c = t.getSelectedColumn();
            if (r >= 0 && c >= 0) {
                clipboard(String.valueOf(t.getValueAt(r, c)));
            }
        });
        menu.add(copyCell);
        t.setComponentPopupMenu(menu);
        t.setCellSelectionEnabled(true);
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JScrollPane(t), BorderLayout.CENTER);
        return p;
    }

    private static JPanel textPanel(JTextArea area) {
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JScrollPane(area), BorderLayout.CENTER);
        return p;
    }

    private JPanel settingsPanel() {
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        top.add(new JLabel("Worker command:"));
        top.add(command);
        top.add(button("Apply / restart", e -> actions.restartWorker(command.getText())));
        command.setToolTipText("How to start the DeepJS engine, e.g.  python -m deepjs serve   (pip install deepjs first)");
        JPanel p = textPanel(log);
        p.add(top, BorderLayout.NORTH);
        return p;
    }

    private static void widths(JTable t, int[] w) {
        for (int i = 0; i < w.length && i < t.getColumnModel().getColumnCount(); i++) {
            t.getColumnModel().getColumn(i).setPreferredWidth(w[i]);
        }
    }

    // ── behaviour ────────────────────────────────────────────────────────────

    private void applyFilter() {
        String text = filter.getText().trim();
        List<RowFilter<KeyedModel, Integer>> all = new ArrayList<>();
        if (!text.isEmpty()) {
            all.add(RowFilter.regexFilter("(?i)" + Pattern.quote(text)));
        }
        if (!showStrings.isSelected()) {
            all.add(RowFilter.notFilter(RowFilter.regexFilter("^string$", E_KIND)));
        }
        endpointSorter.setRowFilter(all.isEmpty() ? null : RowFilter.andFilter(all));
    }

    List<String[]> selectedEndpoints() {
        List<String[]> out = new ArrayList<>();
        for (int viewRow : endpointTable.getSelectedRows()) {
            out.add(endpoints.row(endpointTable.convertRowIndexToModel(viewRow)));
        }
        return out;
    }

    private void copy(List<String[]> rows, int column) {
        StringBuilder b = new StringBuilder();
        for (String[] r : rows) {
            b.append(r[column]).append('\n');
        }
        clipboard(b.toString().trim());
    }

    private static void clipboard(String text) {
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        } catch (RuntimeException ignored) {
            // no clipboard (headless) — nothing to copy to
        }
    }

    private void refreshTitles() {
        tabs.setTitleAt(0, "API calls (" + endpoints.getRowCount() + ")");
        tabs.setTitleAt(1, "Secrets (" + secrets.getRowCount() + ")");
        tabs.setTitleAt(2, "Hidden scripts (" + scripts.getRowCount() + ")");
        tabs.setTitleAt(3, "Hosts (" + hosts.getRowCount() + ")");
    }

    private static void onEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeLater(r);
        }
    }

    // ── updates from the extension (any thread) ──────────────────────────────

    void putEndpoint(String key, String[] row) {
        onEdt(() -> endpoints.upsert(key, row));
    }

    void removeEndpoint(String key) {
        onEdt(() -> endpoints.remove(key));
    }

    void putSecret(String key, String[] row) {
        onEdt(() -> secrets.upsert(key, row));
    }

    void putScript(String url, String kind, String state) {
        onEdt(() -> scripts.upsert(url, new String[]{url, kind, state}));
    }

    void putHost(String[] row) {
        onEdt(() -> hosts.upsert(row[0], row));
    }

    void putOther(String section, String item) {
        onEdt(() -> {
            List<String> items = otherItems.computeIfAbsent(section, k -> new ArrayList<>());
            if (items.contains(item)) {
                return;
            }
            items.add(item);
            StringBuilder b = new StringBuilder();
            otherItems.forEach((name, list) -> {
                b.append(name).append(" (").append(list.size()).append(")\n");
                list.forEach(i -> b.append("    ").append(i).append('\n'));
                b.append('\n');
            });
            other.setText(b.toString());
            other.setCaretPosition(0);
        });
    }

    void log(String line) {
        onEdt(() -> {
            if (log.getLineCount() > 2000) {
                log.setText("");
            }
            log.append(line + "\n");
        });
    }

    void setStatus(String text, boolean healthy) {
        onEdt(() -> {
            status.setText(text);
            status.setForeground(healthy ? new Color(0x2E7D32) : new Color(0xC62828));
        });
    }

    void clearTables() {
        onEdt(() -> {
            endpoints.clear();
            secrets.clear();
            scripts.clear();
            hosts.clear();
            otherItems.clear();
            other.setText("");
        });
    }

    void forEachOption(Consumer<JCheckBox> c) {
        for (JCheckBox box : new JCheckBox[]{enabled, scopeOnly, fetchHidden, fetchMaps, raiseIssues}) {
            c.accept(box);
        }
    }

    // ── renderers ────────────────────────────────────────────────────────────

    private static final class MethodRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
            Component comp = super.getTableCellRendererComponent(t, v, sel, focus, r, c);
            String m = String.valueOf(v);
            if (!sel) {
                comp.setForeground(switch (m) {
                    case "GET" -> new Color(0x2E7D32);
                    case "POST", "PUT", "PATCH" -> new Color(0xB26A00);
                    case "DELETE" -> new Color(0xC62828);
                    default -> Color.GRAY;
                });
            }
            setFont(getFont().deriveFont(Font.BOLD));
            return comp;
        }
    }

    private static final class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
            Component comp = super.getTableCellRendererComponent(t, v, sel, focus, r, c);
            if (!sel) {
                comp.setForeground(switch (String.valueOf(v)) {
                    case "critical", "high" -> new Color(0xC62828);
                    case "medium" -> new Color(0xB26A00);
                    case "low" -> new Color(0x1565C0);
                    default -> Color.GRAY;
                });
            }
            return comp;
        }
    }
}
