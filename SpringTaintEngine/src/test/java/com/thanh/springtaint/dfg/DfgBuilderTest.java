package com.thanh.springtaint.dfg;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.body.MethodDeclaration;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DfgBuilderTest {

    static {
        // Arrow-form switch expression syntax below needs JavaParser's language level bumped
        // past its ancient default -- JavaParserService's static initializer does that
        // globally, but this class must not depend on some other test class happening to load
        // it first.
        new com.thanh.springtaint.parser.JavaParserService();
    }

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

    @Test
    void build_ternaryExpression_mergesBothBranchesIntoTheAssignedVariable() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "String run(String id, boolean flag) { String result = flag ? id : \"default\"; return result; }");

        DataFlowGraph dfg = new DfgBuilder().build(method);

        DfgNode id = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.PARAM && "id".equals(n.variableName()))
                .findFirst().orElseThrow();
        DfgNode result = nodeFor(dfg, "result");

        DfgNode merge = dfg.edges().stream()
                .filter(e -> e.from().equals(id))
                .map(DfgEdge::to)
                .findFirst().orElseThrow();
        assertEquals(DfgNode.Kind.EXPRESSION, merge.kind());
        assertTrue(dfg.edges().stream().anyMatch(e -> e.from().equals(merge) && e.to().equals(result)));
    }

    @Test
    void build_switchExpression_mergesEveryArrowCaseIntoTheAssignedVariable() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "String run(String id, int code) { "
                        + "String result = switch (code) { case 1 -> id; default -> \"default\"; }; "
                        + "return result; }");

        DataFlowGraph dfg = new DfgBuilder().build(method);

        DfgNode id = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.PARAM && "id".equals(n.variableName()))
                .findFirst().orElseThrow();
        DfgNode result = nodeFor(dfg, "result");

        DfgNode merge = dfg.edges().stream()
                .filter(e -> e.from().equals(id))
                .map(DfgEdge::to)
                .findFirst().orElseThrow();
        assertEquals(DfgNode.Kind.EXPRESSION, merge.kind());
        assertTrue(dfg.edges().stream().anyMatch(e -> e.from().equals(merge) && e.to().equals(result)));
    }

    @Test
    void build_switchStatement_walksEveryCaseBodyStructurally() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "void run(int code) { switch (code) { case 1: int a = 1; int b = a; break; } }");

        DataFlowGraph dfg = new DfgBuilder().build(method);

        DfgNode a = nodeFor(dfg, "a");
        DfgNode b = nodeFor(dfg, "b");
        assertTrue(dfg.edges().stream().anyMatch(e -> e.from().equals(a) && e.to().equals(b)));
    }

    @Test
    void build_expressionBodiedLambda_evaluatesItsBodyAgainstTheEnclosingScope() {
        // items.forEach(x -> sink(id)): `id` is a closure over the enclosing method's own
        // parameter, not the lambda's own parameter -- this is the common .forEach()/.map()
        // shape and must stay visible for taint to reach `sink`.
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "void run(String id) { items.forEach(x -> sink(id)); }");

        DataFlowGraph dfg = new DfgBuilder().build(method);

        DfgNode id = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.PARAM && "id".equals(n.variableName()))
                .findFirst().orElseThrow();
        DfgNode sinkCall = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.CALL && n.label().startsWith("sink"))
                .findFirst().orElseThrow();

        assertTrue(dfg.edges().stream()
                .anyMatch(e -> e.from().equals(id) && e.to().equals(sinkCall) && "arg0".equals(e.label())));
    }

    @Test
    void build_blockBodiedLambdaReturn_isNotMisreportedAsTheEnclosingMethodsReturn() {
        // A `return` inside a block-bodied lambda yields the LAMBDA's own value -- it must not
        // produce a Kind.RETURN node, since the taint engine treats any RETURN node as the
        // enclosing method returning and would otherwise mis-route taint to every one of this
        // method's own callers.
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "void run(String id) { items.forEach(x -> { return; }); }");

        DataFlowGraph dfg = new DfgBuilder().build(method);

        assertTrue(dfg.nodes().stream().noneMatch(n -> n.kind() == DfgNode.Kind.RETURN));
    }

    @Test
    void build_constructorCall_isVisibleAsACallNodeLinkedFromItsArguments() {
        // Before ObjectCreationExpr was handled in evaluate(), `new java.io.File(path)` was
        // invisible to the DFG entirely -- `path` never linked to anything, and taint through
        // any constructor call silently vanished.
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "void run(String path) { java.io.File f = new java.io.File(path); }");

        DataFlowGraph dfg = new DfgBuilder().build(method);

        DfgNode path = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.PARAM && "path".equals(n.variableName()))
                .findFirst().orElseThrow();
        DfgNode constructorCall = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.CALL && n.label().contains("new java.io.File"))
                .findFirst().orElseThrow();

        assertTrue(dfg.edges().stream()
                .anyMatch(e -> e.from().equals(path) && e.to().equals(constructorCall) && "arg0".equals(e.label())));
    }

    @Test
    void build_anonymousClassBody_evaluatesTopLevelStatementsAgainstTheEnclosingScope() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "void run(String id) { Runnable r = new Runnable() { public void run() { sink(id); } }; }");

        DataFlowGraph dfg = new DfgBuilder().build(method);

        DfgNode id = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.PARAM && "id".equals(n.variableName()))
                .findFirst().orElseThrow();
        DfgNode sinkCall = dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.CALL && n.label().startsWith("sink"))
                .findFirst().orElseThrow();

        assertTrue(dfg.edges().stream()
                .anyMatch(e -> e.from().equals(id) && e.to().equals(sinkCall) && "arg0".equals(e.label())));
    }

    @Test
    void build_anonymousClassMethodReturn_isNotMisreportedAsTheEnclosingMethodsReturn() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "void run() { java.util.Comparator<String> c = new java.util.Comparator<String>() { "
                        + "public int compare(String a, String b) { return 0; } }; }");

        DataFlowGraph dfg = new DfgBuilder().build(method);

        assertTrue(dfg.nodes().stream().noneMatch(n -> n.kind() == DfgNode.Kind.RETURN));
    }

    private static DfgNode nodeFor(DataFlowGraph dfg, String variableName) {
        return dfg.nodes().stream()
                .filter(n -> n.kind() == DfgNode.Kind.ASSIGN && variableName.equals(n.variableName()))
                .reduce((first, second) -> second) // last definition of that name
                .orElseThrow();
    }
}
