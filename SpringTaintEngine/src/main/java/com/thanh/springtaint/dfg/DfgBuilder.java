package com.thanh.springtaint.dfg;

import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.ConditionalExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.LambdaExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.SwitchExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.stmt.ForStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.SwitchEntry;
import com.github.javaparser.ast.stmt.SwitchStmt;
import com.github.javaparser.ast.stmt.TryStmt;
import com.github.javaparser.ast.stmt.WhileStmt;
import com.github.javaparser.ast.stmt.YieldStmt;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builds an intraprocedural Data Flow Graph for a single method: which variables'
 * values were used to compute each new variable value, method-call argument, or
 * return expression.
 *
 * Simplifications (deferred, not yet handled):
 * - Branches (if/else, switch, while/for bodies) are each walked from an independent
 *   snapshot of the reaching-definition map and then joined at the branch's end (see
 *   {@link #branchAndMerge}) -- a variable that could hold a different value depending
 *   on which branch ran becomes a synthetic {@link DfgNode.Kind#MERGE} node linking
 *   every possibility, rather than one branch's last-assigned value silently
 *   overwriting every other one. This is still not fully flow-sensitive: branches are
 *   not aware of which conditions are mutually exclusive or statically impossible
 *   (e.g. a condition built from constants that always evaluates the same way), and a
 *   loop body is approximated as "runs zero or one times" (no fixpoint over multiple
 *   iterations). Good enough for taint reachability, which only needs "could this
 *   value have come from here", not "which branch definitely ran".
 * - try/catch/finally is walked structurally (try body, every catch body, finally
 *   body all visited, sharing one map with no merge -- an exception can occur at any
 *   point inside the try body, so treating every statement after it as unreachable
 *   would lose real dataflow) but not control-flow-accurately: a catch clause's
 *   exception parameter (e.g. the {@code e} in {@code catch (SQLException e)}) is
 *   never registered as a tracked variable, so data derived from the caught exception
 *   itself is invisible -- only the case that actually matters for taint (values
 *   computed before an exception could occur, e.g. a tainted query built right before
 *   {@code executeQuery}) is what this fix targets.
 * - No type resolution: variable references are matched purely by identifier name
 *   (JavaSymbolSolver is not wired up), so fields/statics with the same name as a
 *   local are not distinguished.
 * - Collections/builders are tracked coarsely, not per-element: a call to a known
 *   mutating method (add/put/append/...) on a simple local-variable receiver makes
 *   that variable's new reaching definition the call itself (which already links the
 *   collection's prior value and the new argument) -- see {@link #updateReceiverIfMutating}.
 *   This means the whole collection is "tainted" the moment anything tainted goes in,
 *   with no notion of which key/index/element -- sound for reachability, not precise.
 */
public class DfgBuilder {

    private List<DfgNode> nodes;
    private List<DfgEdge> edges;
    private int nextId;
    private Map<String, DfgNode> currentDefs;

    public DataFlowGraph build(MethodDeclaration method) {
        return buildFrom(method.getParameters(), method.getBody().orElse(null));
    }

    /** Same intraprocedural analysis, for a constructor body -- see {@link #evaluateObjectCreation}. */
    public DataFlowGraph build(ConstructorDeclaration constructor) {
        return buildFrom(constructor.getParameters(), constructor.getBody());
    }

    private DataFlowGraph buildFrom(NodeList<Parameter> parameters, BlockStmt body) {
        nodes = new ArrayList<>();
        edges = new ArrayList<>();
        nextId = 0;
        currentDefs = new LinkedHashMap<>();

        for (Parameter parameter : parameters) {
            String name = parameter.getNameAsString();
            DfgNode paramNode = newNode(DfgNode.Kind.PARAM, name, name);
            currentDefs.put(name, paramNode);
        }

        if (body != null) {
            processStatements(body.getStatements());
        }

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
        } else if (statement.isSwitchStmt()) {
            processSwitch(statement.asSwitchStmt());
        }
        // other statement kinds (do-while, etc.) are not walked yet.
    }

    private void processSwitch(SwitchStmt switchStmt) {
        evaluate(switchStmt.getSelector());
        List<SwitchEntry> entries = switchStmt.getEntries();
        if (entries.isEmpty()) {
            return;
        }
        List<Runnable> branches = new ArrayList<>();
        boolean hasDefault = false;
        for (SwitchEntry entry : entries) {
            branches.add(() -> processStatements(entry.getStatements()));
            if (entry.getLabels().isEmpty()) {
                hasDefault = true;
            }
        }
        if (!hasDefault) {
            // No case matched is itself a reachable outcome -- an implicit no-op branch so
            // that outcome's reaching definitions (i.e. "nothing changed") are part of the join.
            branches.add(() -> { });
        }
        // Classic switch fall-through (a case with no `break`) is not modeled: every case's
        // statements are walked as an independent branch from the pre-switch state, not
        // chained into the next case. Consistent with this builder's overall bias toward
        // "sound enough for reachability" over exact control-flow semantics.
        branchAndMerge(branches);
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
        branchAndMerge(List.of(
                () -> processStatement(ifStmt.getThenStmt()),
                () -> ifStmt.getElseStmt().ifPresent(this::processStatement)));
    }

    private void processWhile(WhileStmt whileStmt) {
        evaluate(whileStmt.getCondition());
        // Approximated as "runs zero or one times": a real loop can also run many times, but
        // the two-branch join (body-once vs. not-at-all) already captures the case that
        // actually matters for taint -- a value assigned only inside the loop must not
        // silently overwrite the value that reaches code after the loop when it never ran.
        branchAndMerge(List.of(
                () -> processStatement(whileStmt.getBody()),
                () -> { }));
    }

    private void processFor(ForStmt forStmt) {
        for (Expression init : forStmt.getInitialization()) {
            processExpressionStatement(init);
        }
        forStmt.getCompare().ifPresent(this::evaluate);
        branchAndMerge(List.of(
                () -> {
                    processStatement(forStmt.getBody());
                    for (Expression update : forStmt.getUpdate()) {
                        processExpressionStatement(update);
                    }
                },
                () -> { }));
    }

    /**
     * Runs every branch independently from its own snapshot of the current reaching-definition
     * map, then joins the results at the end: a variable whose value is the exact same node
     * across every branch keeps that node (nothing to merge -- untouched or touched identically
     * everywhere); one that diverges gets a synthetic {@link DfgNode.Kind#MERGE} node with an
     * incoming edge from each distinct value seen, becoming the reaching definition going
     * forward. Passing a no-op branch (a {@code Runnable} that does nothing) represents "this
     * alternative leaves everything as it already was" -- how an {@code if} with no
     * {@code else}, a {@code switch} with no {@code default}, and a loop that might run zero
     * times are all expressed in terms of this same join.
     */
    private void branchAndMerge(List<Runnable> branches) {
        Map<String, DfgNode> before = currentDefs;
        List<Map<String, DfgNode>> results = new ArrayList<>();
        for (Runnable branch : branches) {
            currentDefs = new LinkedHashMap<>(before);
            branch.run();
            results.add(currentDefs);
        }
        currentDefs = mergeDefs(results);
    }

    private Map<String, DfgNode> mergeDefs(List<Map<String, DfgNode>> branchResults) {
        Map<String, DfgNode> merged = new LinkedHashMap<>();
        Set<String> allVars = new LinkedHashSet<>();
        for (Map<String, DfgNode> result : branchResults) {
            allVars.addAll(result.keySet());
        }
        for (String variable : allVars) {
            Set<DfgNode> distinctValues = new LinkedHashSet<>();
            for (Map<String, DfgNode> result : branchResults) {
                DfgNode value = result.get(variable);
                if (value != null) {
                    distinctValues.add(value);
                }
            }
            if (distinctValues.size() == 1) {
                merged.put(variable, distinctValues.iterator().next());
            } else if (distinctValues.size() > 1) {
                DfgNode mergeNode = newNode(DfgNode.Kind.MERGE, variable, variable + " (merged)");
                for (DfgNode value : distinctValues) {
                    linkIfPresent(value, mergeNode, "merge");
                }
                merged.put(variable, mergeNode);
            }
        }
        return merged;
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
        if (expr.isConditionalExpr()) {
            return evaluateConditional(expr.asConditionalExpr());
        }
        if (expr.isSwitchExpr()) {
            return evaluateSwitchExpr(expr.asSwitchExpr());
        }
        if (expr.isLambdaExpr()) {
            return evaluateLambda(expr.asLambdaExpr());
        }
        if (expr.isObjectCreationExpr()) {
            return evaluateObjectCreation(expr.asObjectCreationExpr());
        }
        if (expr.isArrayInitializerExpr()) {
            return evaluateArrayInitializer(expr.asArrayInitializerExpr());
        }
        if (expr.isArrayCreationExpr()) {
            // `new String[] {a, b}` is a distinct JavaParser node from the bare `{a, b}` above
            // (ArrayCreationExpr, not ArrayInitializerExpr) -- e.g. Runtime.exec's
            // `new String[] {cmd, tainted}` argument shape.
            return expr.asArrayCreationExpr().getInitializer()
                    .map(this::evaluateArrayInitializer)
                    .orElse(null);
        }
        return null;
    }

    /**
     * An array literal ({@code {"echo", cmd}}) merges every element into one node, the same
     * flow-insensitive join used for binary/ternary/switch expressions above -- this is what
     * lets taint reach a sink argument built as {@code String[] envp = {tainted};} rather than
     * passed as a bare variable (e.g. {@code Runtime.exec(cmdarray, envp)}).
     */
    private DfgNode evaluateArrayInitializer(com.github.javaparser.ast.expr.ArrayInitializerExpr array) {
        DfgNode merge = newNode(DfgNode.Kind.EXPRESSION, null, array.toString());
        boolean anyElementLinked = false;
        for (Expression element : array.getValues()) {
            DfgNode value = evaluate(element);
            if (value != null) {
                linkIfPresent(value, merge, "element");
                anyElementLinked = true;
            }
        }
        return anyElementLinked ? merge : null;
    }

    private DfgNode evaluateConditional(ConditionalExpr conditional) {
        evaluate(conditional.getCondition());
        DfgNode thenValue = evaluate(conditional.getThenExpr());
        DfgNode elseValue = evaluate(conditional.getElseExpr());
        if (thenValue == null && elseValue == null) {
            return null;
        }
        DfgNode merge = newNode(DfgNode.Kind.EXPRESSION, null, conditional.toString());
        linkIfPresent(thenValue, merge, "then");
        linkIfPresent(elseValue, merge, "else");
        return merge;
    }

    /**
     * A switch expression's value is whichever branch is taken; every branch is merged into
     * one node (same flow-insensitive join used for ternary/binary expressions above), whether
     * the branch yields via an arrow ({@code case X -> value}) or an old-style {@code yield}.
     */
    private DfgNode evaluateSwitchExpr(SwitchExpr switchExpr) {
        evaluate(switchExpr.getSelector());
        DfgNode merge = newNode(DfgNode.Kind.EXPRESSION, null, switchExpr.toString());
        boolean anyBranchLinked = false;
        for (SwitchEntry entry : switchExpr.getEntries()) {
            for (Statement stmt : entry.getStatements()) {
                if (stmt.isExpressionStmt()) {
                    linkIfPresent(evaluate(stmt.asExpressionStmt().getExpression()), merge, "case");
                    anyBranchLinked = true;
                }
                for (YieldStmt yield : stmt.findAll(YieldStmt.class)) {
                    linkIfPresent(evaluate(yield.getExpression()), merge, "case");
                    anyBranchLinked = true;
                }
            }
        }
        return anyBranchLinked ? merge : null;
    }

    /**
     * Expression-bodied lambdas ({@code x -> expr}) are evaluated like any other expression,
     * sharing the enclosing method's reaching-definition map -- this makes closures over
     * already-tainted locals visible (e.g. {@code list.forEach(x -> sink(taintedField, x))}).
     * Block-bodied lambdas only have their top-level expression statements walked: a
     * {@code return} inside a lambda block yields the LAMBDA's own value, not the enclosing
     * method's, and this builder has no separate node kind for that -- reusing Kind.RETURN
     * would wrongly make the taint engine treat it as the enclosing method returning, jumping
     * taint back into every one of the enclosing method's callers. Left unmodeled rather than
     * modeled incorrectly; the lambda's own parameter is never registered as a definition
     * either, since nothing here knows what value it's actually invoked with.
     */
    private DfgNode evaluateLambda(LambdaExpr lambda) {
        Statement body = lambda.getBody();
        if (body.isExpressionStmt()) {
            return evaluate(body.asExpressionStmt().getExpression());
        }
        if (body.isBlockStmt()) {
            walkSafeBlockBody(body.asBlockStmt());
        }
        return null;
    }

    /**
     * A constructor call is treated like a method call for taint purposes: its own arguments
     * flow into it (so e.g. {@code new FileInputStream(taintedPath)} can be matched directly
     * as a sink -- see {@link com.thanh.springtaint.rules.SinkCatalog}), and the resulting
     * CALL node stands for "the constructed object" so a chained call on it
     * ({@code new ObjectInputStream(x).readObject()}) still sees the receiver as tainted when
     * {@code x} was. This reuses {@code Kind.CALL} rather than a separate node kind so
     * CallGraphBuilder/TaintEngine need no extra kind-specific handling -- CallGraphBuilder
     * emits a matching {@code CallGraphEdge} for the same call-site text, keyed by the JVM's
     * own constructor-name convention ({@code "<init>"}), which is also how a project-local
     * class's own constructor becomes a jump-able callee.
     *
     * When the expression has an anonymous class body ({@code new Runnable() { ... }}), every
     * method declared in it is also walked, using the same safe subset as block-bodied lambdas
     * (top-level {@code ExpressionStmt} only -- see {@link #evaluateLambda}'s javadoc for why),
     * so taint already in scope via closure capture and used directly inside the body is still
     * visible (e.g. {@code new Runnable() { public void run() { sink(taintedOuterVar); } } }).
     * A framework dispatching into the callback later (Spring's {@code JdbcTemplate} calling a
     * {@code RowMapper}, for instance) is not a call site this engine's static call graph can
     * see at all, with or without this -- that's a fundamentally different, much larger
     * problem (modeling specific frameworks' reflective dispatch) that no purely syntactic/CHA
     * engine can solve generically.
     */
    private DfgNode evaluateObjectCreation(ObjectCreationExpr newExpr) {
        DfgNode node = newNode(DfgNode.Kind.CALL, null, newExpr.toString());
        NodeList<Expression> arguments = newExpr.getArguments();
        for (int i = 0; i < arguments.size(); i++) {
            linkIfPresent(evaluate(arguments.get(i)), node, "arg" + i);
        }
        newExpr.getAnonymousClassBody().ifPresent(this::walkAnonymousClassBody);
        return node;
    }

    private void walkAnonymousClassBody(NodeList<BodyDeclaration<?>> body) {
        for (BodyDeclaration<?> member : body) {
            if (member.isMethodDeclaration()) {
                member.asMethodDeclaration().getBody().ifPresent(this::walkSafeBlockBody);
            }
        }
    }

    /**
     * Walks only top-level {@code ExpressionStmt} statements of a block: a {@code return}
     * (or anything nested inside if/while/etc.) is deliberately left unwalked here rather
     * than modeled incorrectly, since this builder has no separate RETURN-node kind for "this
     * lambda/anonymous method's own return" versus "the enclosing method's return" -- reusing
     * Kind.RETURN would make the taint engine wrongly treat it as the latter and jump taint
     * back into every one of the enclosing method's own callers.
     */
    private void walkSafeBlockBody(BlockStmt block) {
        for (Statement stmt : block.getStatements()) {
            if (stmt.isExpressionStmt()) {
                evaluate(stmt.asExpressionStmt().getExpression());
            }
        }
    }

    /**
     * Method names whose call this builder treats as mutating their receiver in place --
     * {@code List/Set/Map.add|put|offer|push|addFirst|addLast|addAll|putAll} and
     * {@code StringBuilder/StringBuffer.append}. Recognized by name alone (no type
     * resolution), so a project-defined method that happens to share one of these names is
     * also (harmlessly) treated as mutating; a real mutating call that uses a different name
     * (e.g. a custom {@code insert(...)}) is not.
     */
    private static final Set<String> MUTATING_METHOD_NAMES =
            Set.of("add", "addAll", "addFirst", "addLast", "put", "putAll", "append", "offer", "push", "set");

    private DfgNode evaluateMethodCall(MethodCallExpr call) {
        DfgNode callNode = newNode(DfgNode.Kind.CALL, null, call.toString());
        call.getScope().ifPresent(scope -> linkIfPresent(evaluate(scope), callNode, "receiver"));
        NodeList<Expression> arguments = call.getArguments();
        for (int i = 0; i < arguments.size(); i++) {
            linkIfPresent(evaluate(arguments.get(i)), callNode, "arg" + i);
        }
        updateReceiverIfMutating(call, callNode);
        return callNode;
    }

    /**
     * A call like {@code list.add(param)} or {@code sb.append(param)} carries taint into the
     * collection/builder itself, not just into a value returned from this call -- a later
     * {@code list.get(0)} or {@code sb.toString()} needs to see it too. Rather than model
     * List/Map/StringBuilder contents element-by-element (this builder has no notion of
     * indices or keys at all), the whole receiver variable's reaching definition becomes this
     * call node, which already links both the collection's prior value (as "receiver") and
     * the new argument(s) (as "argN") -- so anything read back out of the variable afterward
     * is conservatively treated as possibly tainted, regardless of which key/index it reads.
     */
    private void updateReceiverIfMutating(MethodCallExpr call, DfgNode callNode) {
        if (!MUTATING_METHOD_NAMES.contains(call.getNameAsString())) {
            return;
        }
        call.getScope().filter(Expression::isNameExpr)
                .ifPresent(scope -> currentDefs.put(scope.asNameExpr().getNameAsString(), callNode));
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
