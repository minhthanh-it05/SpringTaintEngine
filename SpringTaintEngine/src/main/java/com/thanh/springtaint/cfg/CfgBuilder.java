package com.thanh.springtaint.cfg;

import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.stmt.ForStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.TryStmt;
import com.github.javaparser.ast.stmt.WhileStmt;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Builds an intraprocedural CFG for a single method body.
 * Supported constructs: sequential statements, if/else, while, for,
 * try/catch/finally (including try-with-resources), return/throw.
 * Not supported yet: switch, do-while, break/continue.
 *
 * try/catch simplifications:
 * - Exception edges are conservative and untyped: every statement inside a try block
 *   gets an edge (labeled "throws") to every one of its catch clauses, regardless of
 *   whether that catch's exception type could actually be thrown there or would
 *   actually catch it -- consistent with the rest of this engine not doing symbol/type
 *   resolution.
 * - A return/throw inside a try or catch jumps straight to EXIT, bypassing any
 *   enclosing finally block. Real Java semantics run the finally block first (and it
 *   can even override the return value); modeling that exactly would mean duplicating
 *   the finally block's CFG at every such exit point, deferred for now.
 */
public class CfgBuilder {

    private List<CfgNode> nodes;
    private List<CfgEdge> edges;
    private int nextId;
    private CfgNode exitNode;

    public ControlFlowGraph build(MethodDeclaration method) {
        nodes = new ArrayList<>();
        edges = new ArrayList<>();
        nextId = 0;

        BlockStmt body = method.getBody()
                .orElseThrow(() -> new IllegalArgumentException("Method has no body: " + method.getNameAsString()));

        CfgNode entry = newNode(CfgNode.Kind.ENTRY, "ENTRY");
        exitNode = newNode(CfgNode.Kind.EXIT, "EXIT");

        Set<CfgNode> tails = buildStatements(body.getStatements(), Set.of(entry), null);
        linkAll(tails, exitNode, null);

        return new ControlFlowGraph(entry, exitNode, List.copyOf(nodes), List.copyOf(edges));
    }

    private Set<CfgNode> buildStatements(NodeList<Statement> statements, Set<CfgNode> preds, String incomingLabel) {
        Set<CfgNode> current = preds;
        String label = incomingLabel;
        for (Statement statement : statements) {
            current = buildStatement(statement, current, label);
            label = null;
        }
        return current;
    }

    private Set<CfgNode> buildStatement(Statement statement, Set<CfgNode> preds, String incomingLabel) {
        if (statement.isBlockStmt()) {
            return buildStatements(statement.asBlockStmt().getStatements(), preds, incomingLabel);
        }
        if (statement.isIfStmt()) {
            return buildIf(statement.asIfStmt(), preds, incomingLabel);
        }
        if (statement.isWhileStmt()) {
            return buildWhile(statement.asWhileStmt(), preds, incomingLabel);
        }
        if (statement.isForStmt()) {
            return buildFor(statement.asForStmt(), preds, incomingLabel);
        }
        if (statement.isReturnStmt() || statement.isThrowStmt()) {
            return buildTerminal(statement, preds, incomingLabel);
        }
        if (statement.isTryStmt()) {
            return buildTry(statement.asTryStmt(), preds, incomingLabel);
        }
        return buildLeaf(statement, preds, incomingLabel);
    }

    private Set<CfgNode> buildLeaf(Statement statement, Set<CfgNode> preds, String incomingLabel) {
        CfgNode node = newNode(CfgNode.Kind.STATEMENT, describe(statement));
        linkAll(preds, node, incomingLabel);
        return Set.of(node);
    }

    private Set<CfgNode> buildTerminal(Statement statement, Set<CfgNode> preds, String incomingLabel) {
        CfgNode node = newNode(CfgNode.Kind.STATEMENT, describe(statement));
        linkAll(preds, node, incomingLabel);
        addEdge(node, exitNode, null);
        return Set.of();
    }

    private Set<CfgNode> buildIf(IfStmt ifStmt, Set<CfgNode> preds, String incomingLabel) {
        CfgNode condition = newNode(CfgNode.Kind.CONDITION, "if (" + ifStmt.getCondition() + ")");
        linkAll(preds, condition, incomingLabel);

        Set<CfgNode> tails = new LinkedHashSet<>(buildStatement(ifStmt.getThenStmt(), Set.of(condition), "true"));

        if (ifStmt.getElseStmt().isPresent()) {
            tails.addAll(buildStatement(ifStmt.getElseStmt().get(), Set.of(condition), "false"));
        } else {
            tails.add(condition);
        }
        return tails;
    }

    private Set<CfgNode> buildWhile(WhileStmt whileStmt, Set<CfgNode> preds, String incomingLabel) {
        CfgNode condition = newNode(CfgNode.Kind.CONDITION, "while (" + whileStmt.getCondition() + ")");
        linkAll(preds, condition, incomingLabel);

        Set<CfgNode> bodyTails = buildStatement(whileStmt.getBody(), Set.of(condition), "true");
        linkAll(bodyTails, condition, null);

        return Set.of(condition);
    }

    private Set<CfgNode> buildFor(ForStmt forStmt, Set<CfgNode> preds, String incomingLabel) {
        Set<CfgNode> current = preds;
        String label = incomingLabel;

        if (!forStmt.getInitialization().isEmpty()) {
            CfgNode init = newNode(CfgNode.Kind.STATEMENT, "for-init: " + describeExpressions(forStmt.getInitialization()));
            linkAll(current, init, label);
            current = Set.of(init);
            label = null;
        }

        CfgNode condition = newNode(CfgNode.Kind.CONDITION,
                forStmt.getCompare().map(c -> "for (" + c + ")").orElse("for (;;)"));
        linkAll(current, condition, label);

        Set<CfgNode> bodyTails = buildStatement(forStmt.getBody(), Set.of(condition), "true");

        if (!forStmt.getUpdate().isEmpty()) {
            CfgNode update = newNode(CfgNode.Kind.STATEMENT, "for-update: " + describeExpressions(forStmt.getUpdate()));
            linkAll(bodyTails, update, null);
            linkAll(Set.of(update), condition, null);
        } else {
            linkAll(bodyTails, condition, null);
        }

        return forStmt.getCompare().isPresent() ? Set.of(condition) : Set.of();
    }

    private Set<CfgNode> buildTry(TryStmt tryStmt, Set<CfgNode> preds, String incomingLabel) {
        Set<CfgNode> current = preds;
        String label = incomingLabel;

        if (!tryStmt.getResources().isEmpty()) {
            CfgNode resources = newNode(CfgNode.Kind.STATEMENT,
                    "try-resources: " + describeExpressions(tryStmt.getResources()));
            linkAll(current, resources, label);
            current = Set.of(resources);
            label = null;
        }

        int beforeTryIndex = nodes.size();
        Set<CfgNode> tryTails = buildStatements(tryStmt.getTryBlock().getStatements(), current, label);
        List<CfgNode> tryBodyNodes = new ArrayList<>(nodes.subList(beforeTryIndex, nodes.size()));

        Set<CfgNode> normalTails = new LinkedHashSet<>(tryTails);
        for (CatchClause catchClause : tryStmt.getCatchClauses()) {
            CfgNode catchEntry = newNode(CfgNode.Kind.STATEMENT, "catch (" + catchClause.getParameter() + ")");
            for (CfgNode tryNode : tryBodyNodes) {
                addEdge(tryNode, catchEntry, "throws");
            }
            normalTails.addAll(buildStatements(catchClause.getBody().getStatements(), Set.of(catchEntry), null));
        }

        if (tryStmt.getFinallyBlock().isPresent()) {
            CfgNode finallyEntry = newNode(CfgNode.Kind.STATEMENT, "finally");
            linkAll(normalTails, finallyEntry, null);
            return buildStatements(tryStmt.getFinallyBlock().get().getStatements(), Set.of(finallyEntry), null);
        }

        return normalTails;
    }

    private String describeExpressions(NodeList<Expression> expressions) {
        return expressions.stream().map(Expression::toString).collect(Collectors.joining(", "));
    }

    private String describe(Statement statement) {
        return statement.toString().strip();
    }

    private void linkAll(Set<CfgNode> preds, CfgNode to, String label) {
        for (CfgNode pred : preds) {
            addEdge(pred, to, label);
        }
    }

    private void addEdge(CfgNode from, CfgNode to, String label) {
        edges.add(new CfgEdge(from, to, label));
    }

    private CfgNode newNode(CfgNode.Kind kind, String label) {
        CfgNode node = new CfgNode(nextId++, kind, label);
        nodes.add(node);
        return node;
    }
}
