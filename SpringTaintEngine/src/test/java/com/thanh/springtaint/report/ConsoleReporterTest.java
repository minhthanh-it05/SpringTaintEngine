package com.thanh.springtaint.report;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.thanh.springtaint.detect.Detector;
import com.thanh.springtaint.detect.Vulnerability;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ConsoleReporterTest {

    private static CompilationUnit sampleControllerUnit() {
        return StaticJavaParser.parse(
                "class SampleController { java.sql.Statement statement; "
                        + "String getUser(@RequestParam String id) throws Exception { "
                        + "  String query = \"SELECT * FROM users WHERE id = \" + id; "
                        + "  return statement.executeQuery(query).toString(); "
                        + "} }");
    }

    @Test
    void render_noFindings_saysSo() {
        String output = new ConsoleReporter().render(List.of());

        assertTrue(output.contains("0 finding(s)"));
        assertTrue(output.contains("No vulnerabilities found."));
    }

    @Test
    void render_withFindings_includesIdSeverityCweAndMessage() {
        List<Vulnerability> vulnerabilities = new Detector().scan(List.of(sampleControllerUnit()));

        String output = new ConsoleReporter().render(vulnerabilities);

        assertTrue(output.contains("SQL_INJECTION-1"));
        assertTrue(output.contains("HIGH"));
        assertTrue(output.contains("CWE-89"));
        assertTrue(output.contains("'id'"));
        assertTrue(output.contains("source: SampleController.getUser/1"));
        assertTrue(output.contains("sink:   Statement.executeQuery/1"));
        assertTrue(output.contains("-> SampleController.getUser/1 #0 PARAM"));
    }

    @Test
    void render_suppressedFinding_isMarkedAndCountedInTheHeader() {
        List<Vulnerability> vulnerabilities = new Detector().scan(List.of(sampleControllerUnit())).stream()
                .map(Vulnerability::asSuppressed)
                .toList();

        String output = new ConsoleReporter().render(vulnerabilities);

        assertTrue(output.contains("(1 already in baseline)"));
        assertTrue(output.contains("[SUPPRESSED - in baseline]"));
    }
}
