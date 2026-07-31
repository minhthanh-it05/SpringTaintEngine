package com.thanh.springtaint.cfg;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.body.MethodDeclaration;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CfgBuilderTest {

    @Test
    void build_straightLineMethod_chainsStatementsSequentially() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "void run() { int a = 1; int b = 2; }");

        ControlFlowGraph cfg = new CfgBuilder().build(method);

        assertEquals(4, cfg.nodes().size()); // entry, 2 statements, exit
        assertEquals(3, cfg.edges().size()); // entry->s1->s2->exit
    }

    @Test
    void build_ifElse_branchesThenRejoinAtExit() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "String run(String id) { if (id == null) { return \"a\"; } else { return \"b\"; } }");

        ControlFlowGraph cfg = new CfgBuilder().build(method);

        assertEquals(5, cfg.nodes().size()); // entry, condition, then-return, else-return, exit
        assertEquals(5, cfg.edges().size());

        long trueEdges = cfg.edges().stream().filter(e -> "true".equals(e.label())).count();
        long falseEdges = cfg.edges().stream().filter(e -> "false".equals(e.label())).count();
        assertEquals(1, trueEdges);
        assertEquals(1, falseEdges);

        long edgesIntoExit = cfg.edges().stream().filter(e -> e.to().equals(cfg.exit())).count();
        assertEquals(2, edgesIntoExit); // both return statements go straight to exit
    }

    @Test
    void build_whileLoop_bodyLoopsBackToCondition() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "void run() { while (true) { doWork(); } }");

        ControlFlowGraph cfg = new CfgBuilder().build(method);

        CfgNode condition = cfg.nodes().stream()
                .filter(n -> n.kind() == CfgNode.Kind.CONDITION)
                .findFirst()
                .orElseThrow();

        CfgNode body = cfg.nodes().stream()
                .filter(n -> n.kind() == CfgNode.Kind.STATEMENT && n.label().contains("doWork"))
                .findFirst()
                .orElseThrow();

        boolean hasBackEdge = cfg.edges().stream()
                .anyMatch(e -> e.from().equals(body) && e.to().equals(condition));
        assertTrue(hasBackEdge);
    }
}
