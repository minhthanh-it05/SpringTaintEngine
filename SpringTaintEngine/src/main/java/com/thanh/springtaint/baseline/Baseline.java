package com.thanh.springtaint.baseline;

import com.thanh.springtaint.detect.Vulnerability;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * A snapshot of previously-seen findings, identified by {@link Vulnerability#fingerprint()},
 * so a later scan can tell "already known" apart from "new" without depending on the sequential
 * {@code id} or line numbers (both drift across unrelated edits -- see that method's javadoc).
 *
 * File format is deliberately plain text, one fingerprint per line, not JSON: this file is
 * meant to be committed and reviewed in a pull request (a teammate approving "yes, we're
 * accepting this finding for now") the same way a `.gitignore`-style file is -- a JSON array of
 * 64-character hashes gives a reviewer nothing to read, while a trailing human-readable comment
 * per line (the finding's id and source/sink methods, written by {@link #write}) lets a diff
 * actually explain what's being accepted. Lines starting with {@code #}, and blank lines, are
 * ignored; parsing only ever reads the first whitespace-delimited token of every other line.
 */
public final class Baseline {

    private final Set<String> fingerprints;

    private Baseline(Set<String> fingerprints) {
        this.fingerprints = fingerprints;
    }

    public static Baseline empty() {
        return new Baseline(Set.of());
    }

    public static Baseline load(Path file) throws IOException {
        Set<String> fingerprints = new LinkedHashSet<>();
        for (String line : Files.readAllLines(file)) {
            String trimmed = line.strip();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            int firstSpace = trimmed.indexOf(' ');
            fingerprints.add(firstSpace < 0 ? trimmed : trimmed.substring(0, firstSpace));
        }
        return new Baseline(fingerprints);
    }

    /**
     * Writes every one of {@code vulnerabilities}' fingerprints to {@code file} -- the "accept
     * everything currently found" action a project runs once, then commits the result, so a
     * future scan only fails CI on genuinely new findings. Overwrites {@code file} entirely;
     * this is a snapshot, not an append-only log.
     */
    public static void write(Path file, List<Vulnerability> vulnerabilities) throws IOException {
        StringBuilder out = new StringBuilder();
        out.append("# SpringTaintEngine baseline -- generated ").append(Instant.now()).append('\n');
        out.append("# Findings whose fingerprint appears here are excluded from --fail-on-findings\n");
        out.append("# gating (still shown in every report, marked as suppressed). Regenerate with\n");
        out.append("# --write-baseline after reviewing and accepting new findings below.\n");
        for (Vulnerability v : vulnerabilities) {
            out.append(v.fingerprint()).append("  ").append(v.id()).append(' ')
                    .append(v.sourceMethod()).append(" -> ").append(v.sinkMethod()).append('\n');
        }
        Files.writeString(file, out.toString());
    }

    public boolean contains(Vulnerability vulnerability) {
        return fingerprints.contains(vulnerability.fingerprint());
    }

    public int size() {
        return fingerprints.size();
    }
}
