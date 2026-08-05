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
                // Same idea as getName, minus the extension -- equally discards every directory
                // component, so equally neutralizes traversal segments.
                new SanitizerRule("FilenameUtils", "getBaseName", 0, "Strips directory components, defeating Path Traversal"),
                // JDK-native equivalent of FilenameUtils.getName: File.getName() returns only the
                // last path segment, discarding any "../" that came before it. Taint here is
                // carried by the *receiver* (e.g. new File(path).getName()), not an argument --
                // RECEIVER_INDEX mirrors how SinkCatalog models new URL(url).openStream().
                new SanitizerRule("File", "getName", SanitizerRule.RECEIVER_INDEX, "Strips directory components, defeating Path Traversal"),

                // UUID coercion: same "structurally can't carry a payload after this" effect as
                // the numeric coercions above, for the common case of an id that should have
                // been a UUID all along.
                new SanitizerRule("UUID", "fromString", 0, "UUID coercion neutralizes injection payloads")

                // Deliberately NOT included:
                // - StringUtils.isNumeric / Pattern.matches: these return a boolean used in an
                //   `if`, they don't transform a value the way every rule above does -- what
                //   they actually neutralize is the *original variable*, and only on the branch
                //   where the check passed. That needs branch-scoped handling, which now lives
                //   in ValidatorCatalog + DfgBuilder#processIf instead of here (see
                //   ValidatorCatalog's javadoc for why it used to be unsound and isn't anymore).
                // - Whitelist-membership checks (e.g. ALLOWED_FILES.contains(param)) for Path
                //   Traversal specifically: same branch-scoping need as above, but not yet added
                //   to ValidatorCatalog -- `contains` is too generic a method name to register
                //   as a validator without a real risk of matching unrelated collections.
                // - Paths.get(...): parses a string into a Path object but does NOT strip "..";
                //   traversal segments survive unchanged. Adding it would be a dangerous FALSE
                //   sanitizer that actively defeats Path Traversal detection instead of fixing it.
                // - File.getCanonicalPath()/getCanonicalFile() and Path.normalize(): both resolve
                //   "." / ".." segments syntactically, but neither one *by itself* proves the
                //   result stays inside an intended base directory -- normalize("base/../../etc/
                //   passwd") still walks out of "base", it just does so without a literal ".."
                //   left in the string. The real fix is normalize-then-check-containment (e.g.
                //   result.startsWith(baseDir)), which is exactly the validator-style, branch-
                //   dependent pattern excluded above: this engine cannot see that the containment
                //   check actually guards the sink. Modeling normalize()/getCanonicalPath() alone
                //   as sanitizers would be unsound -- it would silently clear taint on the most
                //   common *unsafe* real-world Path Traversal pattern (normalize without a
                //   follow-up containment check), trading a false positive for a false negative.
        ));
    }

    public boolean sanitizes(MethodKey callee, int argumentIndex) {
        return rules.stream().anyMatch(rule -> rule.sanitizes(callee, argumentIndex));
    }
}
