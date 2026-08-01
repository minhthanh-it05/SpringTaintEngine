package com.thanh.springtaint.callgraph;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.type.ClassOrInterfaceType;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builds an approximate, whole-project Call Graph: which method calls which other
 * method, across every parsed compilation unit. Walks every {@link TypeDeclaration}
 * (classes, interfaces, enums, records), not just {@link ClassOrInterfaceDeclaration}
 * directly, so record/enum methods are indexed and callable too.
 *
 * There is no symbol solver wired up (same choice as
 * {@link com.thanh.springtaint.dfg.DfgBuilder}), so a call's target class is
 * resolved purely syntactically:
 * - no scope / {@code this.foo()} -> same class as the caller.
 * - {@code x.foo()} where {@code x} is a parameter, local variable, or field with a
 *   known declared type in the parsed sources -> that declared type's simple name.
 * - {@code X.foo()} where {@code X} isn't a known variable -> assumed to be a class
 *   reference (static call), using the identifier itself as the class name; this is
 *   what lets {@code Runtime.getRuntime()} resolve to class {@code Runtime}.
 * - anything else (chained calls, casts, array access, ...) -> callee class is left
 *   as "?" (unknown); the method name/arity are still recorded so the call site
 *   isn't silently dropped from the graph.
 *
 * Interface/abstract dispatch: when the resolved callee has no method body (an
 * interface method or an abstract method -- the common Spring shape of
 * {@code @Autowired private UserService service;} where {@code UserService} is an
 * interface implemented by {@code UserServiceImpl}), this walks the
 * implements/extends hierarchy (transitively, e.g. interface -> abstract base class ->
 * concrete class) and adds one extra edge per concrete override found. This is a
 * simplified Class Hierarchy Analysis: it doesn't know which concrete implementation is
 * actually injected at runtime, so it conservatively fans out to every declared
 * override reachable in the parsed sources rather than picking one -- more recall, less
 * precision, which matches this engine's general preference for not producing false
 * negatives over not producing false positives. The abstract/interface edge itself is
 * always kept too (even when no override is found), so the call is never silently
 * dropped.
 *
 * Classes are matched by simple name only (no import/package resolution), and
 * overloads are disambiguated only by argument count, not by type. Constructor
 * calls ({@code new Foo()}) are not tracked yet. These are the same kind of
 * deferred-precision trade-offs already made in CfgBuilder/DfgBuilder, to keep the
 * engine running end-to-end before tightening accuracy.
 */
public class CallGraphBuilder {

    private static final String UNKNOWN_CLASS = "?";

    public CallGraph build(List<CompilationUnit> units) {
        Map<String, Map<String, String>> fieldTypesByClass = new HashMap<>();
        Map<String, List<String>> subtypesBySupertype = new HashMap<>();
        Set<MethodKey> declaredMethods = new LinkedHashSet<>();
        Map<MethodKey, MethodDeclaration> methodDeclarationsByKey = new HashMap<>();
        List<MethodDeclaration> allMethods = new ArrayList<>();
        Map<MethodDeclaration, String> classNameByMethod = new HashMap<>();

        for (CompilationUnit unit : units) {
            for (TypeDeclaration<?> typeDecl : unit.findAll(TypeDeclaration.class)) {
                String className = typeDecl.getNameAsString();
                fieldTypesByClass.put(className, fieldTypes(typeDecl));
                recordHierarchy(typeDecl, subtypesBySupertype);

                for (MethodDeclaration method : typeDecl.getMethods()) {
                    MethodKey key = new MethodKey(className, method.getNameAsString(), method.getParameters().size());
                    declaredMethods.add(key);
                    methodDeclarationsByKey.put(key, method);
                    allMethods.add(method);
                    classNameByMethod.put(method, className);
                }
            }
        }

        List<CallGraphEdge> edges = new ArrayList<>();
        for (MethodDeclaration method : allMethods) {
            String className = classNameByMethod.get(method);
            MethodKey caller = new MethodKey(className, method.getNameAsString(), method.getParameters().size());
            Map<String, String> localTypes = localTypes(method, fieldTypesByClass.get(className));

            for (MethodCallExpr call : method.findAll(MethodCallExpr.class)) {
                MethodKey primary = resolveCallee(call, className, localTypes);
                for (MethodKey callee : resolveDispatchTargets(primary, declaredMethods, methodDeclarationsByKey,
                        subtypesBySupertype)) {
                    edges.add(new CallGraphEdge(caller, callee, call.toString()));
                }
            }
        }

        return new CallGraph(declaredMethods, edges);
    }

    /** Records {@code typeDecl}'s implemented interfaces and extended super-type(s) for dispatch resolution. */
    private void recordHierarchy(TypeDeclaration<?> typeDecl, Map<String, List<String>> subtypesBySupertype) {
        if (!(typeDecl instanceof ClassOrInterfaceDeclaration classOrInterface)) {
            return;
        }
        String className = classOrInterface.getNameAsString();
        for (ClassOrInterfaceType implemented : classOrInterface.getImplementedTypes()) {
            subtypesBySupertype.computeIfAbsent(implemented.getNameAsString(), k -> new ArrayList<>()).add(className);
        }
        for (ClassOrInterfaceType extended : classOrInterface.getExtendedTypes()) {
            subtypesBySupertype.computeIfAbsent(extended.getNameAsString(), k -> new ArrayList<>()).add(className);
        }
    }

    /**
     * Expands {@code primary} into every callee this call site could actually reach: itself,
     * plus -- when it has no body (interface/abstract dispatch) -- every concrete override
     * found by walking the implements/extends hierarchy transitively.
     */
    private Set<MethodKey> resolveDispatchTargets(MethodKey primary, Set<MethodKey> declaredMethods,
                                                    Map<MethodKey, MethodDeclaration> methodDeclarationsByKey,
                                                    Map<String, List<String>> subtypesBySupertype) {
        if (hasBody(primary, methodDeclarationsByKey)) {
            return Set.of(primary);
        }

        Set<MethodKey> resolved = new LinkedHashSet<>();
        resolved.add(primary);
        Set<String> visitedClasses = new HashSet<>();
        Deque<String> toVisit = new ArrayDeque<>(subtypesBySupertype.getOrDefault(primary.className(), List.of()));

        while (!toVisit.isEmpty()) {
            String subtype = toVisit.poll();
            if (!visitedClasses.add(subtype)) {
                continue;
            }
            MethodKey candidate = new MethodKey(subtype, primary.methodName(), primary.paramCount());
            if (declaredMethods.contains(candidate) && hasBody(candidate, methodDeclarationsByKey)) {
                resolved.add(candidate);
            } else {
                // this class doesn't provide a concrete override itself -- keep descending
                // (covers both "doesn't declare the method at all" and "declares it abstract too").
                toVisit.addAll(subtypesBySupertype.getOrDefault(subtype, List.of()));
            }
        }

        return resolved;
    }

    private boolean hasBody(MethodKey key, Map<MethodKey, MethodDeclaration> methodDeclarationsByKey) {
        MethodDeclaration declaration = methodDeclarationsByKey.get(key);
        return declaration != null && declaration.getBody().isPresent();
    }

    private Map<String, String> fieldTypes(TypeDeclaration<?> typeDecl) {
        Map<String, String> fieldTypes = new HashMap<>();
        for (FieldDeclaration field : typeDecl.getFields()) {
            String type = simpleTypeName(field.getElementType().asString());
            for (VariableDeclarator variable : field.getVariables()) {
                fieldTypes.put(variable.getNameAsString(), type);
            }
        }
        return fieldTypes;
    }

    private Map<String, String> localTypes(MethodDeclaration method, Map<String, String> fieldTypes) {
        Map<String, String> localTypes = new HashMap<>();
        if (fieldTypes != null) {
            localTypes.putAll(fieldTypes);
        }
        for (Parameter parameter : method.getParameters()) {
            localTypes.put(parameter.getNameAsString(), simpleTypeName(parameter.getType().asString()));
        }
        for (VariableDeclarator variable : method.findAll(VariableDeclarator.class)) {
            localTypes.put(variable.getNameAsString(), simpleTypeName(variable.getType().asString()));
        }
        return localTypes;
    }

    private MethodKey resolveCallee(MethodCallExpr call, String callerClassName, Map<String, String> localTypes) {
        String methodName = call.getNameAsString();
        int argCount = call.getArguments().size();

        String calleeClass = call.getScope()
                .map(scope -> resolveScopeClass(scope, callerClassName, localTypes))
                .orElse(callerClassName);
        return new MethodKey(calleeClass, methodName, argCount);
    }

    private String resolveScopeClass(Expression scope, String callerClassName, Map<String, String> localTypes) {
        if (scope.isThisExpr()) {
            return callerClassName;
        }
        if (scope.isNameExpr()) {
            String name = scope.asNameExpr().getNameAsString();
            String type = localTypes.get(name);
            if (type != null) {
                return type;
            }
            return Character.isUpperCase(name.charAt(0)) ? name : UNKNOWN_CLASS;
        }
        return UNKNOWN_CLASS;
    }

    private String simpleTypeName(String type) {
        String withoutGenerics = type.contains("<") ? type.substring(0, type.indexOf('<')) : type;
        int lastDot = withoutGenerics.lastIndexOf('.');
        return lastDot >= 0 ? withoutGenerics.substring(lastDot + 1) : withoutGenerics;
    }
}
