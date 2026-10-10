package deepjs.burp;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Owns the engine process (`python -m deepjs serve`) and speaks its line protocol.
 *
 * Nothing in this class depends on Burp, so the bridge between the extension
 * and the engine can be exercised on its own (see Harness).
 *
 * Starting: each candidate command is tried in turn until one answers READY.
 * A worker that was running and dies is restarted by the next submission; a
 * worker that cannot be started is left alone until {@link #start()} is called
 * again, so a missing interpreter is reported once and not on every response.
 */
final class Worker {

    interface Listener {
        /** One protocol message from the worker, already split and unescaped. */
        void onMessage(String[] fields);

        void onState(String text, boolean healthy);

        void onLog(String text);
    }

    private static final int START_TIMEOUT_SECONDS = 20;

    private final Listener listener;
    private final ExecutorService writer = Executors.newSingleThreadExecutor(r -> daemon(r, "deepjs-writer"));
    private final AtomicInteger pending = new AtomicInteger();
    private final AtomicLong ids = new AtomicLong();
    private volatile List<List<String>> commands;
    private volatile String enginePath = "";
    private volatile Process process;
    private volatile BufferedWriter stdin;
    private volatile String version = "";
    private volatile boolean ready;            // the current process has answered READY
    private volatile boolean restartable = true;
    private volatile boolean stopping;

    Worker(List<String> command, Listener listener) {
        this.commands = List.of(new ArrayList<>(command));
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

    // ── configuration ────────────────────────────────────────────────────────

    /** The commands to try, in order; the first one that answers READY is used. */
    void setCommands(List<List<String>> candidates) {
        List<List<String>> copy = new ArrayList<>();
        for (List<String> c : candidates) {
            if (!c.isEmpty()) {
                copy.add(new ArrayList<>(c));
            }
        }
        this.commands = copy;
    }

    /** A directory (or `archive.jar/dir`) that holds the `deepjs` package; put first on the engine's import path. */
    void setEnginePath(String path) {
        this.enginePath = path == null ? "" : path;
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

    /** Start (or restart) the engine and wait for it to answer. Returns true when it is usable. */
    synchronized boolean start() {
        stopProcess();
        stopping = false;
        pending.set(0);
        version = "";
        List<List<String>> candidates = commands;
        if (candidates.isEmpty()) {
            return failed("no Python command is configured");
        }
        String firstError = null;
        try {
            for (List<String> command : candidates) {
                String error = launch(command);
                if (error == null) {
                    restartable = true;
                    listener.onState("engine ready — deepjs " + version, true);
                    return true;
                }
                if (firstError == null) {
                    firstError = error;
                } else {
                    listener.onLog("also tried " + error);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
        return failed(firstError);
    }

    private boolean failed(String why) {
        restartable = false;
        listener.onState("engine not started: " + why, false);
        return false;
    }

    /** Run one command and wait for READY. Returns null on success, otherwise what went wrong. */
    private String launch(List<String> command) throws InterruptedException {
        String shown = "\"" + String.join(" ", command) + "\"";
        Process p;
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            Map<String, String> env = pb.environment();
            env.put("PYTHONIOENCODING", "utf-8");
            env.put("PYTHONUTF8", "1");
            env.put("PYTHONUNBUFFERED", "1");
            env.put("DEEPJS_NO_UPDATE_CHECK", "1");          // the extension checks, through Burp's networking
            if (!enginePath.isEmpty()) {
                String inherited = env.get("PYTHONPATH");
                env.put("PYTHONPATH", inherited == null || inherited.isBlank()
                        ? enginePath : enginePath + File.pathSeparator + inherited);
            }
            p = pb.start();
        } catch (IOException e) {
            return shown + " could not be run (" + e.getMessage() + ")";
        }
        process = p;
        ready = false;
        stdin = new BufferedWriter(new OutputStreamWriter(p.getOutputStream(), StandardCharsets.UTF_8), 1 << 16);
        CountDownLatch answered = new CountDownLatch(1);
        StringBuilder stderr = new StringBuilder();
        Thread errors = daemon(() -> readStderr(p, stderr), "deepjs-stderr");
        daemon(() -> readStdout(p, answered), "deepjs-reader").start();
        errors.start();

        boolean signalled = answered.await(START_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        if (signalled && !version.isEmpty()) {
            ready = true;
            return null;
        }
        String why;
        if (signalled) {
            // stdout closed without READY: the process is exiting; give it a moment to say why
            p.waitFor(2, TimeUnit.SECONDS);
            errors.join(500);
            why = p.isAlive() ? "it closed its output without starting" : "it exited with code " + p.exitValue();
        } else {
            why = "no answer within " + START_TIMEOUT_SECONDS + " s";
        }
        String said;
        synchronized (stderr) {
            said = stderr.toString().trim();
        }
        stopProcess();
        return shown + ": " + why + (said.isEmpty() ? "" : " — " + lastLine(said));
    }

    private static String lastLine(String text) {
        String[] lines = text.split("\\R");
        String line = lines[lines.length - 1].trim();
        return line.length() > 300 ? line.substring(0, 300) + "…" : line;
    }

    private void readStdout(Process p, CountDownLatch answered) {
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
                        answered.countDown();
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
            answered.countDown();
            if (!stopping && p == process && ready) {
                ready = false;
                pending.set(0);
                listener.onState("engine stopped unexpectedly — it restarts on the next response", false);
            }
        }
    }

    private void readStderr(Process p, StringBuilder collected) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(p.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                synchronized (collected) {
                    if (collected.length() < 8192) {
                        collected.append(line).append('\n');
                    }
                }
                if (ready) {
                    listener.onLog("engine: " + line);     // start-up errors are reported once, by launch()
                }
            }
        } catch (IOException ignored) {
            // nothing to do
        }
    }

    private synchronized boolean ensureStarted() {
        return alive() || (restartable && start());
    }

    /**
     * Queue one response body for analysis. kind = auto | script | html | map. Never blocks the caller.
     * Returns false when the engine is down and will not be restarted automatically, so nothing was queued.
     */
    boolean submit(String kind, String url, byte[] body) {
        if (stopping || (!alive() && !restartable)) {
            return false;
        }
        pending.incrementAndGet();
        writer.execute(() -> {
            try {
                if (!ensureStarted()) {
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
                listener.onLog("could not send " + url + " to the engine: " + e.getMessage());
            }
        });
        return true;
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
        ready = false;
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
