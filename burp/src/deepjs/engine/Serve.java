package deepjs.engine;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/**
 * The engine behind the same line protocol as the Python package's
 * `deepjs serve`, so that the two can be fed the same input and compared
 * line for line (burp/parity.py):
 *
 *     java -cp deepjs-burp.jar deepjs.engine.Serve [--reveal] [--entropy]
 *
 * UTF-8, tab-separated, one message per line; tab, line feed, carriage return
 * and backslash are escaped inside fields.
 *
 *   in    A <id> <kind> <url> <base64 body>     analyse; kind = auto | script | html | map
 *         RESET | PING | QUIT
 *   out   READY deepjs <version>, then the records of {@link Engine#flush}, then  D <id>
 *         X <message> for an input that could not be analysed (never fatal)
 */
public final class Serve {

    /** The version of the analysis rules; equal to the Python package's `__version__`. */
    public static final String VERSION = "0.4.0";

    private Serve() {
    }

    public static void main(String[] args) throws IOException {
        boolean reveal = List.of(args).contains("--reveal");
        boolean entropy = List.of(args).contains("--entropy");
        PrintStream out = new PrintStream(System.out, false, StandardCharsets.UTF_8);
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8), 1 << 16);
        Engine engine = new Engine(entropy);
        send(out, "READY", "deepjs", VERSION);
        for (String line = in.readLine(); line != null; line = in.readLine()) {
            String[] parts = line.split("\t", -1);
            String command = parts[0];
            if (command.equals("A") && parts.length >= 5) {
                String url = unescape(parts[3]);
                try {
                    String kind = parts[2];
                    engine.feed(url, Base64.getDecoder().decode(parts[4]), Py.in(kind, "auto", "script", "html", "map") ? kind : "auto");
                    for (String[] record : engine.flush(reveal)) {
                        send(out, record);
                    }
                } catch (RuntimeException | StackOverflowError e) {         // one bad input must not stop the worker
                    String message = url + ": " + e.getClass().getSimpleName() + ": " + e.getMessage();
                    send(out, "X", message.length() > 300 ? message.substring(0, 300) : message);
                }
                send(out, "D", parts[1]);
            } else if (command.equals("PING")) {
                send(out, "PONG");
            } else if (command.equals("RESET")) {
                engine = new Engine(entropy);
                send(out, "OK");
            } else if (command.equals("QUIT")) {
                break;
            } else if (!command.isEmpty()) {
                send(out, "X", "unknown command: " + (command.length() > 40 ? command.substring(0, 40) : command));
            }
        }
        out.flush();
    }

    private static void send(PrintStream out, String... fields) {
        StringBuilder line = new StringBuilder();
        for (int i = 0; i < fields.length; i++) {
            if (i > 0) {
                line.append('\t');
            }
            escape(fields[i], line);
        }
        out.print(line.append('\n'));
        out.flush();
    }

    private static void escape(String field, StringBuilder into) {
        for (int i = 0; i < field.length(); i++) {
            char c = field.charAt(i);
            switch (c) {
                case '\\' -> into.append("\\\\");
                case '\t' -> into.append("\\t");
                case '\n' -> into.append("\\n");
                case '\r' -> into.append("\\r");
                default -> into.append(c);
            }
        }
    }

    private static String unescape(String field) {
        if (field.indexOf('\\') < 0) {
            return field;
        }
        StringBuilder out = new StringBuilder(field.length());
        for (int i = 0; i < field.length(); i++) {
            char c = field.charAt(i);
            if (c == '\\' && i + 1 < field.length()) {
                char next = field.charAt(++i);
                out.append(next == 't' ? '\t' : next == 'n' ? '\n' : next == 'r' ? '\r' : next);
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
