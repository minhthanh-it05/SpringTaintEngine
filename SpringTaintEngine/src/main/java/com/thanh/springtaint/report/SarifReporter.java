package com.thanh.springtaint.report;

import com.thanh.springtaint.detect.Vulnerability;
import com.thanh.springtaint.rules.Severity;
import com.thanh.springtaint.rules.VulnerabilityType;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * SARIF 2.1.0 report writer -- the industry-standard static analysis format, consumed by
 * GitHub Code Scanning, VS Code's SARIF viewer, and most CI security dashboards. Hand-rolled
 * (no JSON library), same rationale as {@link JsonReporter}: the schema this engine actually
 * needs is fixed and shallow, so a bespoke writer is simpler than pulling in a general-purpose
 * dependency for it. Only the subset of SARIF needed to render one result per finding with a
 * rule catalog and a source-code location is implemented -- no fixes/suggestions, no
 * multi-location flow graphs (the JSON report's {@code path} array already covers that need
 * in this engine's own format).
 */
public class SarifReporter implements Reporter {

    private static final String SCHEMA =
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

    @Override
    public String render(List<Vulnerability> vulnerabilities) {
        Set<VulnerabilityType> rulesUsed = new LinkedHashSet<>();
        for (Vulnerability v : vulnerabilities) {
            rulesUsed.add(v.type());
        }

        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"$schema\": ").append(quote(SCHEMA)).append(",\n");
        json.append("  \"version\": \"2.1.0\",\n");
        json.append("  \"runs\": [\n");
        json.append("    {\n");
        json.append("      \"tool\": {\n");
        json.append("        \"driver\": {\n");
        json.append("          \"name\": \"SpringTaintEngine\",\n");
        json.append("          \"informationUri\": \"https://github.com/minhthanh-it05/SpringTaintEngine\",\n");
        json.append("          \"version\": \"1.0.0\",\n");
        json.append("          \"rules\": [\n");
        appendRules(json, rulesUsed);
        json.append("          ]\n");
        json.append("        }\n");
        json.append("      },\n");
        json.append("      \"results\": [\n");
        appendResults(json, vulnerabilities);
        json.append("      ]\n");
        json.append("    }\n");
        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private void appendRules(StringBuilder json, Set<VulnerabilityType> rulesUsed) {
        int i = 0;
        for (VulnerabilityType type : rulesUsed) {
            json.append("            {\n");
            json.append("              \"id\": ").append(quote(type.name())).append(",\n");
            json.append("              \"name\": ").append(quote(type.displayName())).append(",\n");
            json.append("              \"shortDescription\": { \"text\": ").append(quote(type.displayName())).append(" },\n");
            json.append("              \"helpUri\": ").append(quote(cweUri(type.cweId()))).append(",\n");
            json.append("              \"properties\": { \"tags\": [\"security\", ")
                    .append(quote("external/cwe/" + type.cweId().toLowerCase())).append("] }\n");
            json.append("            }");
            json.append(++i < rulesUsed.size() ? ",\n" : "\n");
        }
    }

    private void appendResults(StringBuilder json, List<Vulnerability> vulnerabilities) {
        for (int i = 0; i < vulnerabilities.size(); i++) {
            Vulnerability v = vulnerabilities.get(i);
            json.append("        {\n");
            json.append("          \"ruleId\": ").append(quote(v.type().name())).append(",\n");
            json.append("          \"level\": ").append(quote(sarifLevel(v.severity()))).append(",\n");
            json.append("          \"message\": { \"text\": ").append(quote(v.message())).append(" }");

            // Prefer the sink location (where the dangerous call actually happens); fall back
            // to the source location; omit locations entirely when neither is known (e.g. the
            // sink is external library code with no file in the scanned project).
            String file = v.sinkFile() != null ? v.sinkFile() : v.sourceFile();
            int line = v.sinkFile() != null ? v.sinkLine() : v.sourceLine();
            if (file != null && line >= 0) {
                json.append(",\n");
                json.append("          \"locations\": [\n");
                json.append("            {\n");
                json.append("              \"physicalLocation\": {\n");
                json.append("                \"artifactLocation\": { \"uri\": ").append(quote(toUri(file))).append(" },\n");
                json.append("                \"region\": { \"startLine\": ").append(Math.max(line, 1)).append(" }\n");
                json.append("              }\n");
                json.append("            }\n");
                json.append("          ]\n");
            } else {
                json.append('\n');
            }

            json.append("        }");
            json.append(i < vulnerabilities.size() - 1 ? ",\n" : "\n");
        }
    }

    private String sarifLevel(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW -> "note";
        };
    }

    private String cweUri(String cweId) {
        return "https://cwe.mitre.org/data/definitions/" + cweId.replace("CWE-", "") + ".html";
    }

    /** SARIF artifact URIs are forward-slash paths, not OS-native ones. */
    private String toUri(String file) {
        return file.replace('\\', '/');
    }

    private String quote(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 2);
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
