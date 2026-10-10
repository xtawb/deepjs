package deepjs.burp;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Owns the `deepjs serve` process and speaks its line protocol.
 *
 * Nothing in this class depends on Burp, so the bridge between the extension
 * and the Python engine can be exercised on its own (see Harness).
 */
final class Worker {

    interface Listener {
        /** One protocol message from the worker, already split and unescaped. */
        void onMessage(String[] fields);

        void onState(String text, boolean healthy);

        void onLog(String text);
    }

    private final Listener listener;
    private final ExecutorService writer = Executors.newSingleThreadExecutor(r -> daemon(r, "deepjs-writer"));
    private final AtomicInteger pending = new AtomicInteger();
    private final AtomicLong ids = new AtomicLong();
    private volatile List<String> command;
    private volatile Process process;
    private volatile BufferedWriter stdin;
    private volatile String version = "";
    private volatile boolean stopping;

    Worker(List<String> command, Listener listener) {
        this.command = new ArrayList<>(command);
        this.listener = listener;
    }

    private static Thread daemon(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        return t;
    }

    // ── protocol encoding ────────────────────────────────────────────────────

    static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder b = null;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            String rep = c == '\\' ? "\\\\" : c == '\t' ? "\\t" : c == '\n' ? "\\n" : c == '\r' ? "\\r" : null;
            if (rep != null && b == null) {
                b = new StringBuilder(s.length() + 8).append(s, 0, i);
            }
            if (b != null) {
                if (rep != null) {
                    b.append(rep);
                } else {
                    b.append(c);
                }
            }
        }
        return b == null ? s : b.toString();
    }

    static String unesc(String s) {
        if (s.indexOf('\\') < 0) {
            return s;
        }
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                b.append(n == 't' ? '\t' : n == 'n' ? '\n' : n == 'r' ? '\r' : n);
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }

    static String[] parse(String line) {
        String[] raw = line.split("\t", -1);
        for (int i = 0; i < raw.length; i++) {
            raw[i] = unesc(raw[i]);
        }
        return raw;
    }

    /** Split a command line into arguments, honouring single and double quotes. */
    static List<String> splitCommand(String text) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        char quote = 0;
        boolean any = false;
        for (char c : text.trim().toCharArray()) {
            if (quote != 0) {
                if (c == quote) {
                    quote = 0;
                } else {
                    cur.append(c);
                }
            } else if (c == '"' || c == '\'') {
                quote = c;
                any = true;
            } else if (Character.isWhitespace(c)) {
                if (cur.length() > 0 || any) {
                    out.add(cur.toString());
                    cur.setLength(0);
                    any = false;
                }
            } else {
                cur.append(c);
            }
        }
        if (cur.length() > 0 || any) {
            out.add(cur.toString());
        }
        return out;
    }

    // ── lifecycle ────────────────────────────────────────────────────────────

    String version() {
        return version;
    }

    int pending() {
        return pending.get();
    }

    boolean alive() {
        Process p = process;
        return p != null && p.isAlive();
    }

    void setCommand(List<String> command) {
        this.command = new ArrayList<>(command);
    }

    /** Start the worker and wait for its READY line. Returns true when it is usable. */
    synchronized boolean start() {
        stopProcess();
        stopping = false;
        pending.set(0);
        version = "";
        if (command.isEmpty()) {
            listener.onState("no worker command configured", false);
            return false;
        }
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.environment().put("PYTHONIOENCODING", "utf-8");
            pb.environment().put("PYTHONUTF8", "1");
            pb.environment().put("PYTHONUNBUFFERED", "1");
            Process p = pb.start();
            process = p;
            stdin = new BufferedWriter(new OutputStreamWriter(p.getOutputStream(), StandardCharsets.UTF_8), 1 << 16);
            CountDownLatch ready = new CountDownLatch(1);
            daemon(() -> readStdout(p, ready), "deepjs-reader").start();
            daemon(() -> readStderr(p), "deepjs-stderr").start();
            if (!ready.await(20, TimeUnit.SECONDS) || version.isEmpty()) {
                String why = p.isAlive() ? "no READY line within 20s" : "process exited with code " + p.exitValue();
                listener.onState("worker failed to start: " + why, false);
                stopProcess();
                return false;
            }
            listener.onState("worker ready — deepjs " + version, true);
            return true;
        } catch (IOException e) {
            listener.onState("cannot run \"" + String.join(" ", command) + "\": " + e.getMessage(), false);
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private void readStdout(Process p, CountDownLatch ready) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                if (line.isEmpty()) {
                    continue;
                }
                String[] f = parse(line);
                switch (f[0]) {
                    case "READY" -> {
                        version = f.length > 2 ? f[2] : "?";
                        ready.countDown();
                    }
                    case "D" -> {
                        pending.updateAndGet(v -> Math.max(0, v - 1));
                        listener.onMessage(f);
                    }
                    case "PONG", "OK" -> { }
                    default -> listener.onMessage(f);
                }
            }
        } catch (IOException ignored) {
            // the process went away; reported below
        } finally {
            ready.countDown();
            if (!stopping && p == process) {
                pending.set(0);
                listener.onState("worker stopped unexpectedly — it restarts on the next response", false);
            }
        }
    }

    private void readStderr(Process p) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(p.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                listener.onLog("worker: " + line);
            }
        } catch (IOException ignored) {
            // nothing to do
        }
    }

    /** Queue one response body for analysis. kind = auto | script | html | map. Never blocks the caller. */
    void submit(String kind, String url, byte[] body) {
        if (stopping) {
            return;
        }
        pending.incrementAndGet();
        writer.execute(() -> {
            try {
                if (!alive() && !start()) {
                    pending.updateAndGet(v -> Math.max(0, v - 1));
                    return;
                }
                String line = "A\t" + ids.incrementAndGet() + "\t" + kind + "\t" + esc(url) + "\t"
                        + Base64.getEncoder().encodeToString(body) + "\n";
                BufferedWriter w = stdin;
                w.write(line);
                w.flush();
            } catch (IOException e) {
                pending.updateAndGet(v -> Math.max(0, v - 1));
                listener.onLog("could not send " + url + " to the worker: " + e.getMessage());
            }
        });
    }

    void reset() {
        writer.execute(() -> {
            try {
                if (alive()) {
                    stdin.write("RESET\n");
                    stdin.flush();
                }
            } catch (IOException ignored) {
                // a dead worker has nothing to forget
            }
        });
    }

    private void stopProcess() {
        Process p = process;
        process = null;
        if (p == null) {
            return;
        }
        try {
            BufferedWriter w = stdin;
            if (w != null && p.isAlive()) {
                w.write("QUIT\n");
                w.flush();
                w.close();
            }
        } catch (IOException ignored) {
            // already gone
        }
        try {
            if (!p.waitFor(2, TimeUnit.SECONDS)) {
                p.destroyForcibly();
            }
        } catch (InterruptedException e) {
            p.destroyForcibly();
            Thread.currentThread().interrupt();
        }
    }

    /** Stop for good (extension unload). */
    void shutdown() {
        stopping = true;
        writer.shutdownNow();
        stopProcess();
    }

    /** Wait until everything submitted so far has been answered (used by tests). */
    boolean awaitIdle(long millis) throws InterruptedException {
        long end = System.currentTimeMillis() + millis;
        while (pending.get() > 0 && System.currentTimeMillis() < end) {
            Thread.sleep(25);
        }
        return pending.get() == 0;
    }
}
