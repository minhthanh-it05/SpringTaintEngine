package com.thanh.springtaint.dfg;

import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.stmt.ForStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.TryStmt;
import com.github.javaparser.ast.stmt.WhileStmt;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds an intraprocedural Data Flow Graph for a single method: which variables'
 * values were used to compute each new variable value, method-call argument, or
 * return expression.
 *
 * Simplifications (deferred, not yet handled):
 * - Flow-insensitive across branches: if/else, loop bodies, and try/catch/finally are
 *   all walked in source order sharing one reaching-definition map, so a definition
 *   made only inside one branch simply overwrites the map for whatever runs after it
 *   (no merge at join points). Good enough while the engine is being made to run
 *   end-to-end; revisit once M8 taint propagation needs branch-sensitive accuracy.
 * - try/catch/finally is walked structurally (try body, every catch body, finally
 *   body all visited) but not control-flow-accurately: a catch clause's exception
 *   parameter (e.g. the {@code e} in {@code catch (SQLException e)}) is never
 *   registered as a tracked variable, so data derived from the caught exception itself
 *   is invisible -- only the case that actually matters for taint (values computed
 *   before an exception could occur, e.g. a tainted query built right before
 *   {@code executeQuery}) is what this fix targets.
 * - No type resolution: variable references are matched purely by identifier name
 *   (JavaSymbolSolver is not wired up), so fields/statics with the same name as a
 *   local are not distinguished.
 */
public class DfgBuilder {

    private List<DfgNode> nodes;
    private List<DfgEdge> edges;
    private int nextId;
    private Map<String, DfgNode> currentDefs;

    public DataFlowGraph build(MethodDeclaration method) {
        nodes = new ArrayList<>();
        edges = new ArrayList<>();
        nextId = 0;
        currentDefs = new LinkedHashMap<>();

        for (Parameter parameter : method.getParameters()) {
            String name = parameter.getNameAsString();
            DfgNode paramNode = newNode(DfgNode.Kind.PARAM, name, name);
            currentDefs.put(name, paramNode);
        }

        method.getBody().ifPresent(body -> processStatements(body.getStatements()));

        return new DataFlowGraph(List.copyOf(nodes), List.copyOf(edges));
    }

    private void processStatements(NodeList<Statement> statements) {
        for (Statement statement : statements) {
            processStatement(statement);
        }
    }

    private void processStatement(Statement statement) {
        if (statement.isBlockStmt()) {
            processStatements(statement.asBlockStmt().getStatements());
        } else if (statement.isExpressionStmt()) {
            processExpressionStatement(statement.asExpressionStmt().getExpression());
        } else if (statement.isIfStmt()) {
            processIf(statement.asIfStmt());
        } else if (statement.isWhileStmt()) {
            processWhile(statement.asWhileStmt());
        } else if (statement.isForStmt()) {
            processFor(statement.asForStmt());
        } else if (statement.isReturnStmt()) {
            statement.asReturnStmt().getExpression().ifPresent(expr -> {
                DfgNode returnNode = newNode(DfgNode.Kind.RETURN, null, "return " + expr);
                linkIfPresent(evaluate(expr), returnNode, "value");
            });
        } else if (statement.isThrowStmt()) {
            evaluate(statement.asThrowStmt().getExpression());
        } else if (statement.isTryStmt()) {
            processTry(statement.asTryStmt());
        }
        // other statement kinds (switch, do-while, etc.) are not walked yet.
    }

    private void processTry(TryStmt tryStmt) {
        for (Expression resource : tryStmt.getResources()) {
            processExpressionStatement(resource);
        }
        processStatements(tryStmt.getTryBlock().getStatements());
        for (CatchClause catchClause : tryStmt.getCatchClauses()) {
            processStatements(catchClause.getBody().getStatements());
        }
        tryStmt.getFinallyBlock().ifPresent(finallyBlock -> processStatements(finallyBlock.getStatements()));
    }

    private void processIf(IfStmt ifStmt) {
        evaluate(ifStmt.getCondition());
        processStatement(ifStmt.getThenStmt());
        ifStmt.getElseStmt().ifPresent(this::processStatement);
    }

    private void processWhile(WhileStmt whileStmt) {
        evaluate(whileStmt.getCondition());
        processStatement(whileStmt.getBody());
    }

    private void processFor(ForStmt forStmt) {
        for (Expression init : forStmt.getInitialization()) {
            processExpressionStatement(init);
        }
        forStmt.getCompare().ifPresent(this::evaluate);
        processStatement(forStmt.getBody());
        for (Expression update : forStmt.getUpdate()) {
            processExpressionStatement(update);
        }
    }

    private void processExpressionStatement(Expression expr) {
        if (expr.isVariableDeclarationExpr()) {
            for (VariableDeclarator declarator : expr.asVariableDeclarationExpr().getVariables()) {
                DfgNode defNode = newNode(DfgNode.Kind.ASSIGN, declarator.getNameAsString(), declarator.toString());
                declarator.getInitializer().ifPresent(init -> linkIfPresent(evaluate(init), defNode, "value"));
                currentDefs.put(declarator.getNameAsString(), defNode);
            }
        } else if (expr.isAssignExpr()) {
            processAssign(expr.asAssignExpr());
        } else {
            evaluate(expr);
        }
    }

    private void processAssign(AssignExpr assign) {
        if (!assign.getTarget().isNameExpr()) {
            evaluate(assign.getValue());
            return;
        }
        String name = assign.getTarget().asNameExpr().getNameAsString();
        DfgNode defNode = newNode(DfgNode.Kind.ASSIGN, name, assign.toString());
        linkIfPresent(evaluate(assign.getValue()), defNode, "value");
        if (assign.getOperator() != AssignExpr.Operator.ASSIGN) {
            // compound assignment (e.g. +=) also reads the previous value of the variable
            linkIfPresent(currentDefs.get(name), defNode, "previous");
        }
        currentDefs.put(name, defNode);
    }

    /**
     * Evaluates an expression, returning the DfgNode that represents its value so a
     * caller can link "value flows into X". Also registers a CALL node, as a side
     * effect, for every method invocation found while descending into the
     * expression -- even ones whose result is discarded -- so a tainted argument
     * reaching e.g. {@code statement.executeQuery(query)} is visible in the graph.
     * Returns null when the expression carries no traceable value (literal, unknown
     * field/static reference, etc.).
     */
    private DfgNode evaluate(Expression expr) {
        if (expr.isNameExpr()) {
            return currentDefs.get(expr.asNameExpr().getNameAsString());
        }
        if (expr.isMethodCallExpr()) {
            return evaluateMethodCall(expr.asMethodCallExpr());
        }
        if (expr.isBinaryExpr()) {
            DfgNode left = evaluate(expr.asBinaryExpr().getLeft());
            DfgNode right = evaluate(expr.asBinaryExpr().getRight());
            if (left == null && right == null) {
                return null;
            }
            DfgNode merge = newNode(DfgNode.Kind.EXPRESSION, null, expr.toString());
            linkIfPresent(left, merge, "left");
            linkIfPresent(right, merge, "right");
            return merge;
        }
        if (expr.isEnclosedExpr()) {
            return evaluate(expr.asEnclosedExpr().getInner());
        }
        if (expr.isCastExpr()) {
            return evaluate(expr.asCastExpr().getExpression());
        }
        if (expr.isUnaryExpr()) {
            return evaluate(expr.asUnaryExpr().getExpression());
        }
        if (expr.isAssignExpr()) {
            processAssign(expr.asAssignExpr());
            return currentDefs.get(assignTargetName(expr.asAssignExpr()));
        }
        return null;
    }

    private DfgNode evaluateMethodCall(MethodCallExpr call) {
        DfgNode callNode = newNode(DfgNode.Kind.CALL, null, call.toString());
        call.getScope().ifPresent(scope -> linkIfPresent(evaluate(scope), callNode, "receiver"));
        NodeList<Expression> arguments = call.getArguments();
        for (int i = 0; i < arguments.size(); i++) {
            linkIfPresent(evaluate(arguments.get(i)), callNode, "arg" + i);
        }
        return callNode;
    }

    private String assignTargetName(AssignExpr assign) {
        return assign.getTarget().isNameExpr() ? assign.getTarget().asNameExpr().getNameAsString() : null;
    }

    private void linkIfPresent(DfgNode from, DfgNode to, String label) {
        if (from != null) {
            edges.add(new DfgEdge(from, to, label));
        }
    }

    private DfgNode newNode(DfgNode.Kind kind, String variableName, String label) {
        DfgNode node = new DfgNode(nextId++, kind, variableName, label);
        nodes.add(node);
        return node;
    }
}
