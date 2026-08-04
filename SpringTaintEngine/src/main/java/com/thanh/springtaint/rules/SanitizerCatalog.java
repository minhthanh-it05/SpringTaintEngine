package com.thanh.springtaint.rules;

import com.thanh.springtaint.callgraph.MethodKey;

import java.util.List;

/**
 * Registry of calls known to neutralize taint on one of their arguments -- the counterpart
 * to {@link SinkCatalog}. Without this, the taint engine has no way to represent "this data
 * was validated/escaped/coerced", so any code that does sanitize its input before reaching a
 * sink is still reported as a false positive.
 */
public class SanitizerCatalog {

    private final List<SanitizerRule> rules;

    public SanitizerCatalog(List<SanitizerRule> rules) {
        this.rules = List.copyOf(rules);
    }

    public static SanitizerCatalog defaults() {
        return new SanitizerCatalog(List.of(
                // Numeric coercion: a SQL/command injection payload cannot survive being
                // parsed as a number -- either the call throws (caught, aborting the flow)
                // or the result is a primitive that can no longer carry the payload.
                new SanitizerRule("Integer", "parseInt", 0, "Numeric coercion neutralizes injection payloads"),
                new SanitizerRule("Integer", "valueOf", 0, "Numeric coercion neutralizes injection payloads"),
                new SanitizerRule("Long", "parseLong", 0, "Numeric coercion neutralizes injection payloads"),
                new SanitizerRule("Long", "valueOf", 0, "Numeric coercion neutralizes injection payloads"),
                new SanitizerRule("Double", "parseDouble", 0, "Numeric coercion neutralizes injection payloads"),

                // Spring's own HTML-escaping helper, the idiomatic fix for reflected XSS.
                new SanitizerRule("HtmlUtils", "htmlEscape", 0, "HTML-encodes special characters, defeating XSS"),

                // URL-encoding a value before it reaches an outbound request/path defeats
                // SSRF/path-traversal payloads that rely on unescaped separators.
                new SanitizerRule("URLEncoder", "encode", 0, "URL-encodes special characters, defeating SSRF/path payloads"),

                // Apache Commons Text/Lang3's escaping helpers -- widely used in real Spring
                // Boot code as the manual fix for XSS/SQLi when a prepared statement or
                // templating engine's own auto-escaping isn't in play.
                new SanitizerRule("StringEscapeUtils", "escapeHtml4", 0, "HTML-encodes special characters, defeating XSS"),
                new SanitizerRule("StringEscapeUtils", "escapeSql", 0, "Escapes SQL metacharacters, defeating SQL Injection"),
                // Pre-3.x Apache Commons Lang used "escapeHtml" (no "4" suffix) -- still shows
                // up in real/legacy code. Surfaced by a 50-case OWASP Benchmark run: fixing the
                // null-guard idiom bug let taint reach this call for the first time, exposing
                // that only the commons-lang3 method name was registered.
                new SanitizerRule("StringEscapeUtils", "escapeHtml", 0, "HTML-encodes special characters, defeating XSS"),

                // Jsoup's HTML sanitizer -- strips dangerous markup/attributes rather than just
                // escaping, the common choice when the output legitimately needs to allow some
                // HTML (e.g. a rich-text comment field) instead of encoding everything.
                new SanitizerRule("Jsoup", "clean", 0, "Strips dangerous markup/attributes, defeating XSS"),

                // Takes just the filename component, discarding any directory traversal
                // segments ("../") -- the standard Apache Commons IO fix for Path Traversal.
                new SanitizerRule("FilenameUtils", "getName", 0, "Strips directory components, defeating Path Traversal"),

                // UUID coercion: same "structurally can't carry a payload after this" effect as
                // the numeric coercions above, for the common case of an id that should have
                // been a UUID all along.
                new SanitizerRule("UUID", "fromString", 0, "UUID coercion neutralizes injection payloads")

                // Deliberately NOT included:
                // - StringUtils.isNumeric / Pattern.matches and other validator-style checks:
                //   these return a boolean used in an `if`, they don't transform the value --
                //   and this engine is flow-insensitive across branches (see DfgBuilder's
                //   javadoc), so there is no reliable way to say "only the validated branch is
                //   safe" yet. Modeling them as sanitizers here would create false negatives
                //   (silently trusting a value whose validation branch was never actually taken).
                // - Paths.get(...): parses a string into a Path object but does NOT strip "..";
                //   traversal segments survive unchanged. Adding it would be a dangerous FALSE
                //   sanitizer that actively defeats Path Traversal detection instead of fixing it.
        ));
    }

    public boolean sanitizes(MethodKey callee, int argumentIndex) {
        return rules.stream().anyMatch(rule -> rule.sanitizes(callee, argumentIndex));
    }
}
