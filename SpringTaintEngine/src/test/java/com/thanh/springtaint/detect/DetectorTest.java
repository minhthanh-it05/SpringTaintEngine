package com.thanh.springtaint.detect;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.thanh.springtaint.rules.Severity;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DetectorTest {

    @Test
    void scan_sqlInjection_producesClassifiedVulnerability() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class SampleController { java.sql.Statement statement; "
                        + "String getUser(@RequestParam String id) throws Exception { "
                        + "  String query = \"SELECT * FROM users WHERE id = \" + id; "
                        + "  return statement.executeQuery(query).toString(); "
                        + "} }");

        List<Vulnerability> vulnerabilities = new Detector().scan(List.of(unit));

        assertEquals(1, vulnerabilities.size());
        Vulnerability vulnerability = vulnerabilities.get(0);
        assertEquals("SQL_INJECTION-1", vulnerability.id());
        assertEquals(Severity.HIGH, vulnerability.severity());
        assertEquals("CWE-89", vulnerability.cweId());
        assertEquals("SQL Injection", vulnerability.title());
        assertTrue(vulnerability.message().contains("'id'"));
        assertTrue(vulnerability.message().contains("@RequestParam"));
        assertTrue(vulnerability.message().contains("statement.executeQuery(query)"));
    }

    @Test
    void scan_commandInjection_usesCriticalSeverityAndCorrectCwe() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class Runner { void run(@RequestParam String cmd) { "
                        + "  Runtime.getRuntime().exec(cmd); "
                        + "} }");

        List<Vulnerability> vulnerabilities = new Detector().scan(List.of(unit));

        assertEquals(1, vulnerabilities.size());
        Vulnerability vulnerability = vulnerabilities.get(0);
        assertEquals("COMMAND_INJECTION-1", vulnerability.id());
        assertEquals(Severity.CRITICAL, vulnerability.severity());
        assertEquals("CWE-78", vulnerability.cweId());
    }

    @Test
    void scan_multipleFindingsOfSameType_getSequentialIds() {
        CompilationUnit a = StaticJavaParser.parse(
                "class A { java.sql.Statement statement; "
                        + "String run(@RequestParam String x) throws Exception { return statement.executeQuery(x).toString(); } }");
        CompilationUnit b = StaticJavaParser.parse(
                "class B { java.sql.Statement statement; "
                        + "String run(@RequestParam String y) throws Exception { return statement.executeQuery(y).toString(); } }");

        List<Vulnerability> vulnerabilities = new Detector().scan(List.of(a, b));

        assertEquals(2, vulnerabilities.size());
        Set<String> ids = vulnerabilities.stream().map(Vulnerability::id).collect(Collectors.toSet());
        assertEquals(Set.of("SQL_INJECTION-1", "SQL_INJECTION-2"), ids);
        assertTrue(vulnerabilities.stream().allMatch(v -> v.severity() == Severity.HIGH));
        assertTrue(vulnerabilities.stream().allMatch(v -> v.cweId().equals("CWE-89")));
    }

    @Test
    void scan_noTaintedSource_producesNoVulnerabilities() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class SampleController { java.sql.Statement statement; "
                        + "String getUser(String id) throws Exception { "
                        + "  return statement.executeQuery(id).toString(); "
                        + "} }");

        List<Vulnerability> vulnerabilities = new Detector().scan(List.of(unit));

        assertTrue(vulnerabilities.isEmpty());
    }

    @Test
    void scan_rawCompilationUnits_haveNoFileButStillHaveADeclarationLine() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class SampleController { java.sql.Statement statement; "
                        + "String getUser(@RequestParam String id) throws Exception { "
                        + "  return statement.executeQuery(id).toString(); "
                        + "} }");

        List<Vulnerability> vulnerabilities = new Detector().scan(List.of(unit));

        assertEquals(1, vulnerabilities.size());
        Vulnerability vulnerability = vulnerabilities.get(0);
        assertNull(vulnerability.sourceFile());
        assertTrue(vulnerability.sourceLine() > 0);
    }

    @Test
    void scanProject_populatesFileAndLine_butLeavesExternalSinkLocationUnknown() throws IOException {
        List<Vulnerability> vulnerabilities = new Detector().scanProject(Path.of("src/main/resources/samples"));

        Vulnerability finding = vulnerabilities.stream()
                .filter(v -> v.sourceMethod().className().equals("SampleController"))
                .findFirst().orElseThrow();

        assertTrue(finding.sourceFile() != null && finding.sourceFile().endsWith("SampleController.java"));
        assertTrue(finding.sourceLine() > 0);
        // Statement.executeQuery is JDK code, not part of the parsed project -> no location.
        assertNull(finding.sinkFile());
        assertEquals(-1, finding.sinkLine());
    }
}
