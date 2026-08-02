package com.thanh.springtaint.taint;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.thanh.springtaint.rules.TaintRules;
import com.thanh.springtaint.rules.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TaintEngineTest {

    @Test
    void analyze_intraproceduralSqlInjection_isFound() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class SampleController { "
                        + "String getUser(@RequestParam String id, java.sql.Statement statement) throws Exception { "
                        + "  String query = \"SELECT * FROM users WHERE id = \" + id; "
                        + "  return statement.executeQuery(query).toString(); "
                        + "} }");

        List<TaintFinding> findings = new TaintEngine(List.of(unit), TaintRules.defaults()).analyze();

        assertEquals(1, findings.size());
        TaintFinding finding = findings.get(0);
        assertEquals("id", finding.source().parameterName());
        assertEquals(VulnerabilityType.SQL_INJECTION, finding.sinkRule().vulnerabilityType());
        assertEquals("Statement", finding.sinkMethod().className());
    }

    @Test
    void analyze_interproceduralSqlInjection_crossesFromControllerIntoService() {
        CompilationUnit controller = StaticJavaParser.parse(
                "class UserController { private UserService userService; "
                        + "String search(@RequestParam String name) throws Exception { "
                        + "  return userService.findByName(name); "
                        + "} }");
        CompilationUnit service = StaticJavaParser.parse(
                "class UserService { private java.sql.Statement statement; "
                        + "String findByName(String name) throws Exception { "
                        + "  String sql = \"SELECT * FROM users WHERE name = \" + name; "
                        + "  return statement.executeQuery(sql).toString(); "
                        + "} }");

        List<TaintFinding> findings = new TaintEngine(List.of(controller, service), TaintRules.defaults()).analyze();

        assertEquals(1, findings.size());
        TaintFinding finding = findings.get(0);
        assertEquals("UserController", finding.sourceMethod().className());
        assertEquals("Statement", finding.sinkMethod().className());
        assertTrue(finding.path().stream().anyMatch(s -> s.method().className().equals("UserController")));
        assertTrue(finding.path().stream().anyMatch(s -> s.method().className().equals("UserService")));
    }

    @Test
    void analyze_contextSensitivity_doesNotLeakTaintIntoAnUnrelatedCallersSink() {
        // riskyOp is a shared helper called from two places: handleTainted passes tainted
        // input into it and routes the result straight into a JDBC sink (must be flagged);
        // handleClean passes a genuinely untainted local parameter into the very same helper
        // and the very same kind of sink (must NOT be flagged). Before 1-call-site-sensitivity
        // was added, a tainted RETURN from riskyOp broadcast back into *every* caller's call
        // site regardless of which caller actually supplied the tainted argument, so
        // handleClean's call site was incorrectly flagged too even though `safe` is never
        // tainted -- this test pins the fix: taint returns only to the call site it actually
        // came from.
        CompilationUnit unit = StaticJavaParser.parse(
                "class Handler { private java.sql.Statement statement; "
                        + "String riskyOp(String userInput) { return userInput; } "
                        + "String handleTainted(@RequestParam String x) throws Exception { "
                        + "  return statement.executeQuery(riskyOp(x)).toString(); } "
                        + "String handleClean(String safe) throws Exception { "
                        + "  return statement.executeQuery(riskyOp(safe)).toString(); } }");

        List<TaintFinding> findings = new TaintEngine(List.of(unit), TaintRules.defaults()).analyze();

        assertEquals(1, findings.size());
        TaintFinding finding = findings.get(0);
        assertEquals("handleTainted", finding.sourceMethod().methodName());
        assertTrue(findings.stream().noneMatch(f -> f.path().stream()
                .anyMatch(s -> s.method().methodName().equals("handleClean"))));
    }

    @Test
    void analyze_untaintedParameter_producesNoFinding() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class SampleController { "
                        + "String getUser(String id, java.sql.Statement statement) throws Exception { "
                        + "  String query = \"SELECT * FROM users WHERE id = \" + id; "
                        + "  return statement.executeQuery(query).toString(); "
                        + "} }");

        List<TaintFinding> findings = new TaintEngine(List.of(unit), TaintRules.defaults()).analyze();

        assertTrue(findings.isEmpty());
    }

    @Test
    void analyze_taintReachingNonSinkCall_producesNoFinding() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class Foo { "
                        + "void log(String msg) { } "
                        + "void run(@RequestParam String id) { "
                        + "  log(id); "
                        + "} }");

        List<TaintFinding> findings = new TaintEngine(List.of(unit), TaintRules.defaults()).analyze();

        assertTrue(findings.isEmpty());
    }

    @Test
    void analyze_sqlInjectionInsideTryCatch_isStillDetected() {
        // The most common real-world JDBC shape: executeQuery wrapped in try/catch for
        // SQLException. Before the DfgBuilder fix this was a hard false negative -- the
        // entire try block was invisible to the DFG, so this test would have found nothing.
        CompilationUnit unit = StaticJavaParser.parse(
                "class SampleController { java.sql.Statement statement; "
                        + "String getUser(@RequestParam String id) { "
                        + "  try { "
                        + "    String query = \"SELECT * FROM users WHERE id = \" + id; "
                        + "    return statement.executeQuery(query).toString(); "
                        + "  } catch (Exception e) { "
                        + "    return \"error\"; "
                        + "  } "
                        + "} }");

        List<TaintFinding> findings = new TaintEngine(List.of(unit), TaintRules.defaults()).analyze();

        assertEquals(1, findings.size());
        assertEquals(VulnerabilityType.SQL_INJECTION, findings.get(0).sinkRule().vulnerabilityType());
    }

    @Test
    void analyze_taintFlowsThroughInterfaceDispatchIntoConcreteImplementation() {
        // The other common real-world Spring shape: a service field typed as an interface.
        // Before the CallGraphBuilder fix this was a hard false negative -- the call resolved
        // only to the body-less interface method, a dead end for taint propagation.
        CompilationUnit iface = StaticJavaParser.parse("interface UserService { String findByName(String name); }");
        CompilationUnit impl = StaticJavaParser.parse(
                "class UserServiceImpl implements UserService { java.sql.Statement statement; "
                        + "public String findByName(String name) throws Exception { "
                        + "  String sql = \"SELECT * FROM users WHERE name = \" + name; "
                        + "  return statement.executeQuery(sql).toString(); "
                        + "} }");
        CompilationUnit controller = StaticJavaParser.parse(
                "class UserController { private UserService userService; "
                        + "String search(@RequestParam String name) throws Exception { "
                        + "  return userService.findByName(name); "
                        + "} }");

        List<TaintFinding> findings =
                new TaintEngine(List.of(iface, impl, controller), TaintRules.defaults()).analyze();

        assertEquals(1, findings.size());
        TaintFinding finding = findings.get(0);
        assertEquals("UserController", finding.sourceMethod().className());
        assertEquals("Statement", finding.sinkMethod().className());
        assertTrue(finding.path().stream().anyMatch(s -> s.method().className().equals("UserServiceImpl")));
    }

    @Test
    void analyze_taintThroughIntegerParseInt_isSanitizedAndProducesNoFinding() {
        // Numeric coercion is the idiomatic real-world fix for "id should have been an int
        // anyway" -- SanitizerCatalog models this, so a value that passes through
        // Integer.parseInt on its way to the sink is no longer reported.
        CompilationUnit unit = StaticJavaParser.parse(
                "class SampleController { java.sql.Statement statement; "
                        + "String getUser(@RequestParam String id) throws Exception { "
                        + "  int numericId = Integer.parseInt(id); "
                        + "  String query = \"SELECT * FROM users WHERE id = \" + numericId; "
                        + "  return statement.executeQuery(query).toString(); "
                        + "} }");

        List<TaintFinding> findings = new TaintEngine(List.of(unit), TaintRules.defaults()).analyze();

        assertTrue(findings.isEmpty());
    }

    @Test
    void analyze_taintFlowsIntoRestTemplateGetForObject_isFlaggedAsSsrf() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class SampleController { RestTemplate restTemplate; "
                        + "String fetch(@RequestParam String url) { "
                        + "  return restTemplate.getForObject(url, String.class); "
                        + "} }");

        List<TaintFinding> findings = new TaintEngine(List.of(unit), TaintRules.defaults()).analyze();

        assertEquals(1, findings.size());
        assertEquals(VulnerabilityType.SSRF, findings.get(0).sinkRule().vulnerabilityType());
    }

    @Test
    void analyze_taintFlowsIntoPrintWriterPrintln_isFlaggedAsXss() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class SampleController { "
                        + "void render(@RequestParam String name, java.io.PrintWriter writer) { "
                        + "  writer.println(name); "
                        + "} }");

        List<TaintFinding> findings = new TaintEngine(List.of(unit), TaintRules.defaults()).analyze();

        assertEquals(1, findings.size());
        assertEquals(VulnerabilityType.CROSS_SITE_SCRIPTING, findings.get(0).sinkRule().vulnerabilityType());
    }

    @Test
    void analyze_readObjectOnATaintedStream_isFlaggedAsInsecureDeserialization() {
        // The danger here is the receiver (the stream itself was built from attacker-controlled
        // bytes), not an argument -- exercises SinkRule.RECEIVER_INDEX end to end.
        CompilationUnit unit = StaticJavaParser.parse(
                "class SampleController { "
                        + "Object load(@RequestParam java.io.ObjectInputStream in) throws Exception { "
                        + "  return in.readObject(); "
                        + "} }");

        List<TaintFinding> findings = new TaintEngine(List.of(unit), TaintRules.defaults()).analyze();

        assertEquals(1, findings.size());
        assertEquals(VulnerabilityType.INSECURE_DESERIALIZATION, findings.get(0).sinkRule().vulnerabilityType());
    }
}
