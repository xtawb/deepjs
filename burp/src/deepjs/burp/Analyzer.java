package deepjs.burp;

import deepjs.engine.Engine;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Runs the analysis engine off Burp's threads.
 *
 * Responses are queued and analysed one at a time on a single background
 * thread — the engine accumulates what it learns across files and is not
 * thread-safe — and whatever is new after each one is handed to the listener.
 * Nothing in this class depends on Burp, so it can be exercised on its own.
 */
final class Analyzer {

    interface Listener {
        /**
         * One record from the engine (see {@link Engine#flush}), or {"D", id}
         * when everything for one submitted response has been delivered.
         */
        void onMessage(String[] fields);

        void onLog(String text);
    }

    /** Bundles nest deeply and some expressions over long strings recurse: give the thread room. */
    private static final long STACK_BYTES = 64L * 1024 * 1024;

    private final Listener listener;
    private final ExecutorService thread = Executors.newSingleThreadExecutor(work -> {
        Thread t = new Thread(null, work, "deepjs-analysis", STACK_BYTES);
        t.setDaemon(true);
        return t;
    });
    private final AtomicInteger pending = new AtomicInteger();
    private final AtomicLong ids = new AtomicLong();
    private Engine engine = new Engine(false);              // touched only on the analysis thread
    private volatile boolean stopped;

    Analyzer(Listener listener) {
        this.listener = listener;
    }

    int pending() {
        return pending.get();
    }

    /**
     * Queue one response body for analysis. kind = auto | script | html | map.
     * Never blocks the caller. Returns false after {@link #shutdown}.
     */
    boolean submit(String kind, String url, byte[] body) {
        if (stopped) {
            return false;
        }
        long id = ids.incrementAndGet();
        pending.incrementAndGet();
        try {
            thread.execute(() -> analyse(id, kind, url, body));
            return true;
        } catch (RejectedExecutionException shuttingDown) {
            pending.decrementAndGet();
            return false;
        }
    }

    private void analyse(long id, String kind, String url, byte[] body) {
        try {
            engine.feed(url, body, kind);
            for (String[] record : engine.flush(false)) {
                listener.onMessage(record);
            }
        } catch (RuntimeException | StackOverflowError e) {
            listener.onLog("could not analyse " + url + ": " + e);         // one bad input must not stop the rest
        } catch (OutOfMemoryError e) {
            engine = new Engine(false);                                     // give the memory back rather than take Burp down
            listener.onLog("out of memory while analysing " + url + " — DeepJS dropped what it had collected");
        } finally {
            pending.decrementAndGet();
            listener.onMessage(new String[]{"D", Long.toString(id)});
        }
    }

    /** Forget everything collected so far. */
    void reset() {
        try {
            thread.execute(() -> engine = new Engine(false));
        } catch (RejectedExecutionException shuttingDown) {
            // nothing left to forget
        }
    }

    /** Stop for good (extension unload). Work already queued is dropped. */
    void shutdown() {
        stopped = true;
        thread.shutdownNow();
    }

    /** Wait until everything submitted so far has been analysed (used by tests). */
    boolean awaitIdle(long millis) throws InterruptedException {
        long end = System.currentTimeMillis() + millis;
        while (pending.get() > 0 && System.currentTimeMillis() < end) {
            Thread.sleep(25);
        }
        return pending.get() == 0;
    }
}
