package com.thanh.springtaint.dfg;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.body.MethodDeclaration;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DfgBuilderTest {

    @Test
    void build_simpleAssignmentChain_linksEachDefToTheNext() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "void run() { int a = 1; int b = a; }");

        DataFlowGraph dfg = new DfgBuilder().build(method);

        DfgNode a = nodeFor(dfg, "a");
        DfgNode b = nodeFor(dfg, "b");

        assertTrue(dfg.edges().stream().anyMatch(e -> e.from().equals(a) && e.to().equals(b)));
    }

    @Test
    void build_stringConcatenationFromParameter_flowsIntoAssignedVariable() {
        // Mirrors SampleController: a @RequestParam value concatenated into a SQL string.
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "String run(String id) { String query = \"SELECT * FROM users WHERE id = \" + id; return query; }");

        DataFlowGraph dfg = new DfgBuilder().build(method);

        DfgNode param = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.PARAM && "id".equals(n.variableName()))
                .findFirst().orElseThrow();
        DfgNode query = nodeFor(dfg, "query");
        DfgNode returnNode = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.RETURN)
                .findFirst().orElseThrow();

        // id -> (merge expr) -> query
        DfgNode merge = dfg.edges().stream()
                .filter(e -> e.from().equals(param))
                .map(DfgEdge::to)
                .findFirst().orElseThrow();
        assertEquals(DfgNode.Kind.EXPRESSION, merge.kind());
        assertTrue(dfg.edges().stream().anyMatch(e -> e.from().equals(merge) && e.to().equals(query)));
        assertTrue(dfg.edges().stream().anyMatch(e -> e.from().equals(query) && e.to().equals(returnNode)));
    }

    @Test
    void build_methodCallArgument_createsCallNodeLinkedFromArgument() {
        // Mirrors a Command Injection sink: Runtime.getRuntime().exec(cmd).
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "void run(String cmd) { process.exec(cmd); }");

        DataFlowGraph dfg = new DfgBuilder().build(method);

        DfgNode cmd = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.PARAM && "cmd".equals(n.variableName()))
                .findFirst().orElseThrow();
        DfgNode call = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.CALL)
                .findFirst().orElseThrow();

        assertTrue(dfg.edges().stream()
                .anyMatch(e -> e.from().equals(cmd) && e.to().equals(call) && "arg0".equals(e.label())));
    }

    @Test
    void build_callInsideTryCatch_isStillVisible() {
        // Regression test: this is the shape of virtually all real JDBC code -- before the
        // fix, DfgBuilder had no handling for TryStmt at all, so a statement wrapped in
        // try/catch was completely invisible (no nodes, no edges), which meant the taint
        // engine could never see a tainted argument reaching a sink guarded by try/catch.
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "void run(String id, java.sql.Statement statement) throws Exception { "
                        + "try { statement.executeQuery(id); } catch (Exception e) { } }");

        DataFlowGraph dfg = new DfgBuilder().build(method);

        DfgNode id = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.PARAM && "id".equals(n.variableName()))
                .findFirst().orElseThrow();
        DfgNode call = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.CALL && n.label().contains("executeQuery"))
                .findFirst().orElseThrow();

        assertTrue(dfg.edges().stream()
                .anyMatch(e -> e.from().equals(id) && e.to().equals(call) && "arg0".equals(e.label())));
    }

    @Test
    void build_assignmentInsideFinally_isStillVisible() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "void run() { try { } finally { int a = 1; int b = a; } }");

        DataFlowGraph dfg = new DfgBuilder().build(method);

        DfgNode a = nodeFor(dfg, "a");
        DfgNode b = nodeFor(dfg, "b");
        assertTrue(dfg.edges().stream().anyMatch(e -> e.from().equals(a) && e.to().equals(b)));
    }

    private static DfgNode nodeFor(DataFlowGraph dfg, String variableName) {
        return dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.ASSIGN && variableName.equals(n.variableName()))
                .reduce((first, second) -> second) // last definition of that name
                .orElseThrow();
    }
}
