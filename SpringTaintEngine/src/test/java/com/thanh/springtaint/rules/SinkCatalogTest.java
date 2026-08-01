package com.thanh.springtaint.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.StaticJavaParser;
import com.thanh.springtaint.callgraph.CallGraph;
import com.thanh.springtaint.callgraph.CallGraphBuilder;
import com.thanh.springtaint.callgraph.CallGraphEdge;
import com.thanh.springtaint.callgraph.MethodKey;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SinkCatalogTest {

    @Test
    void isSink_matchesJdbcExecuteQueryOnArgumentZero() {
        SinkCatalog catalog = SinkCatalog.defaults();
        MethodKey executeQuery = new MethodKey("Statement", "executeQuery", 1);

        assertTrue(catalog.isSink(executeQuery));
        SinkRule rule = catalog.match(executeQuery).get(0);
        assertEquals(VulnerabilityType.SQL_INJECTION, rule.vulnerabilityType());
        assertTrue(rule.isArgumentTainted(0));
        assertFalse(rule.isArgumentTainted(1));
    }

    @Test
    void isSink_wildcardClassMatchesUnresolvedChainedCallToExec() {
        // Runtime.getRuntime().exec(cmd): CallGraphBuilder can't resolve the receiver of a
        // chained call, so it records the callee class as "?" -- the exec sink is
        // deliberately class-agnostic so this still matches.
        SinkCatalog catalog = SinkCatalog.defaults();

        assertTrue(catalog.isSink(new MethodKey("?", "exec", 1)));
        assertTrue(catalog.isSink(new MethodKey("Runtime", "exec", 1)));
        assertTrue(catalog.isSink(new MethodKey("ProcessBuilder", "exec", 0)));
    }

    @Test
    void isSink_unrelatedMethodDoesNotMatch() {
        SinkCatalog catalog = SinkCatalog.defaults();

        assertFalse(catalog.isSink(new MethodKey("UserService", "findByName", 1)));
    }

    @Test
    void match_endToEndWithCallGraph_flagsTheJdbcCallSiteAsASqlInjectionSink() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class UserService { private java.sql.Statement statement; "
                        + "void run(String sql) throws Exception { statement.executeQuery(sql); } }");
        CallGraph callGraph = new CallGraphBuilder().build(List.of(unit));
        SinkCatalog catalog = SinkCatalog.defaults();

        boolean foundSink = false;
        for (CallGraphEdge edge : callGraph.edges()) {
            if (catalog.isSink(edge.callee())) {
                foundSink = true;
                assertEquals(VulnerabilityType.SQL_INJECTION, catalog.match(edge.callee()).get(0).vulnerabilityType());
            }
        }
        assertTrue(foundSink);
    }
}
