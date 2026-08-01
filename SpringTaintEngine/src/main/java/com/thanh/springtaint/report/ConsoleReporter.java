package com.thanh.springtaint.report;

import com.thanh.springtaint.detect.Vulnerability;
import com.thanh.springtaint.taint.PathStep;

import java.util.List;

/** Human-readable, plain-text report: one block per finding plus its full trace path. */
public class ConsoleReporter implements Reporter {

    @Override
    public String render(List<Vulnerability> vulnerabilities) {
        StringBuilder out = new StringBuilder();
        out.append("Taint analysis report - ").append(vulnerabilities.size()).append(" finding(s)\n");
        out.append("=".repeat(60)).append('\n');

        if (vulnerabilities.isEmpty()) {
            out.append("No vulnerabilities found.\n");
            return out.toString();
        }

        for (Vulnerability v : vulnerabilities) {
            out.append('[').append(v.id()).append("] ").append(v.severity())
                    .append(" - ").append(v.title()).append(" (").append(v.cweId()).append(")\n");
            out.append("  ").append(v.message()).append('\n');

            out.append("  source: ").append(v.sourceMethod());
            if (v.sourceFile() != null) {
                out.append(" (").append(v.sourceFile()).append(':').append(v.sourceLine()).append(')');
            }
            out.append('\n');

            out.append("  sink:   ").append(v.sinkMethod());
            if (v.sinkFile() != null) {
                out.append(" (").append(v.sinkFile()).append(':').append(v.sinkLine()).append(')');
            }
            out.append('\n');

            out.append("  path:\n");
            for (PathStep step : v.path()) {
                out.append("    -> ").append(step.method()).append(" #").append(step.node().id())
                        .append(' ').append(step.node().kind());
                if (step.node().label() != null) {
                    out.append(": ").append(step.node().label());
                }
                out.append('\n');
            }
            out.append('\n');
        }

        return out.toString();
    }
}
