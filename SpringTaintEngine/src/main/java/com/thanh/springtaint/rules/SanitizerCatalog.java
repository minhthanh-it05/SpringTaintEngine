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
                new SanitizerRule("URLEncoder", "encode", 0, "URL-encodes special characters, defeating SSRF/path payloads")
        ));
    }

    public boolean sanitizes(MethodKey callee, int argumentIndex) {
        return rules.stream().anyMatch(rule -> rule.sanitizes(callee, argumentIndex));
    }
}
