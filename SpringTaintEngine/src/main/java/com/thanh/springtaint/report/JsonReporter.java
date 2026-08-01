package com.thanh.springtaint.report;

import com.thanh.springtaint.detect.Vulnerability;
import com.thanh.springtaint.taint.PathStep;

import java.util.List;

/**
 * Hand-rolled JSON report writer -- no JSON library dependency, in keeping with the rest
 * of this engine being self-implemented (parser AST walking, CFG/DFG/call graph, taint
 * propagation) rather than delegated to off-the-shelf tools. The schema is fixed and
 * shallow (records of strings/ints/enums/lists), so a bespoke, indentation-fixed writer
 * is simpler and safer than pulling in a general-purpose library for it.
 */
public class JsonReporter implements Reporter {

    @Override
    public String render(List<Vulnerability> vulnerabilities) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"findingCount\": ").append(vulnerabilities.size()).append(",\n");
        json.append("  \"vulnerabilities\": [\n");

        for (int i = 0; i < vulnerabilities.size(); i++) {
            appendVulnerability(json, vulnerabilities.get(i), "    ");
            json.append(i < vulnerabilities.size() - 1 ? ",\n" : "\n");
        }

        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private void appendVulnerability(StringBuilder json, Vulnerability v, String indent) {
        String inner = indent + "  ";
        json.append(indent).append("{\n");
        field(json, inner, "id", v.id());
        field(json, inner, "type", v.type().name());
        field(json, inner, "severity", v.severity().name());
        field(json, inner, "cweId", v.cweId());
        field(json, inner, "title", v.title());
        field(json, inner, "message", v.message());

        json.append(inner).append("\"source\": {\n");
        String sourceIndent = inner + "  ";
        field(json, sourceIndent, "method", v.sourceMethod().toString());
        field(json, sourceIndent, "parameter", v.source().parameterName());
        field(json, sourceIndent, "annotation", v.source().sourceAnnotation());
        field(json, sourceIndent, "file", v.sourceFile());
        rawFieldLast(json, sourceIndent, "line", v.sourceLine() < 0 ? "null" : String.valueOf(v.sourceLine()));
        json.append(inner).append("},\n");

        json.append(inner).append("\"sink\": {\n");
        String sinkIndent = inner + "  ";
        field(json, sinkIndent, "method", v.sinkMethod().toString());
        field(json, sinkIndent, "callSite", v.sinkCallSite());
        field(json, sinkIndent, "file", v.sinkFile());
        rawFieldLast(json, sinkIndent, "line", v.sinkLine() < 0 ? "null" : String.valueOf(v.sinkLine()));
        json.append(inner).append("},\n");

        json.append(inner).append("\"path\": [\n");
        List<PathStep> path = v.path();
        String pathIndent = inner + "  ";
        for (int i = 0; i < path.size(); i++) {
            appendPathStep(json, path.get(i), pathIndent);
            json.append(i < path.size() - 1 ? ",\n" : "\n");
        }
        json.append(inner).append("]\n");

        json.append(indent).append("}");
    }

    private void appendPathStep(StringBuilder json, PathStep step, String indent) {
        json.append(indent).append('{');
        json.append("\"method\": ").append(quote(step.method().toString())).append(", ");
        json.append("\"nodeId\": ").append(step.node().id()).append(", ");
        json.append("\"kind\": ").append(quote(step.node().kind().name())).append(", ");
        json.append("\"label\": ").append(step.node().label() == null ? "null" : quote(step.node().label()));
        json.append('}');
    }

    private void field(StringBuilder json, String indent, String name, String value) {
        json.append(indent).append('"').append(name).append("\": ")
                .append(value == null ? "null" : quote(value)).append(",\n");
    }

    private void rawFieldLast(StringBuilder json, String indent, String name, String rawValue) {
        json.append(indent).append('"').append(name).append("\": ").append(rawValue).append('\n');
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
