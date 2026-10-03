package com.example.proxygateway.ssl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Educational LogCollector.
 *
 * <p>Captures step-by-step diagnostic and learning messages during a TLS handshake probe.
 * The logs are both printed to SLF4J (console) and collected per-thread so they can be
 * returned in the API response and displayed live in the UI for interactive learning.</p>
 */
public class LogCollector {

    private static final Logger log = LoggerFactory.getLogger(LogCollector.class);
    private static final ThreadLocal<List<String>> THREAD_LOGS = ThreadLocal.withInitial(ArrayList::new);
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    public static void start() {
        THREAD_LOGS.get().clear();
    }

    public static void log(String emoji, String message, Object... args) {
        String formatted = (args != null && args.length > 0) ? format(message, args) : message;
        String line = "[" + LocalTime.now().format(TIME_FMT) + "] " + emoji + " " + formatted;
        THREAD_LOGS.get().add(line);
        log.info("{} {}", emoji, formatted);
    }

    public static void debug(String message, Object... args) {
        String formatted = (args != null && args.length > 0) ? format(message, args) : message;
        String line = "[" + LocalTime.now().format(TIME_FMT) + "] 🔍 " + formatted;
        THREAD_LOGS.get().add(line);
        log.debug("🔍 {}", formatted);
    }

    public static void warn(String message, Object... args) {
        String formatted = (args != null && args.length > 0) ? format(message, args) : message;
        String line = "[" + LocalTime.now().format(TIME_FMT) + "] ⚠️ " + formatted;
        THREAD_LOGS.get().add(line);
        log.warn("⚠️ {}", formatted);
    }

    public static void error(String message, Object... args) {
        String formatted = (args != null && args.length > 0) ? format(message, args) : message;
        String line = "[" + LocalTime.now().format(TIME_FMT) + "] ❌ " + formatted;
        THREAD_LOGS.get().add(line);
        log.error("❌ {}", formatted);
    }

    public static List<String> getLogs() {
        return new ArrayList<>(THREAD_LOGS.get());
    }

    public static void clear() {
        THREAD_LOGS.remove();
    }

    private static String format(String template, Object... args) {
        String result = template;
        for (Object arg : args) {
            result = result.replaceFirst("\\{\\}", java.util.regex.Matcher.quoteReplacement(String.valueOf(arg)));
        }
        return result;
    }
}
