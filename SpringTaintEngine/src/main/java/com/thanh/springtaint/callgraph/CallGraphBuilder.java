package com.thanh.springtaint.callgraph;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.resolution.declarations.ResolvedMethodDeclaration;

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
 * Resolution is symbol-solver-first, syntactic-heuristic-fallback: when the
 * {@code CompilationUnit} a call belongs to had a {@code JavaSymbolSolver} injected into it
 * (done by {@link com.thanh.springtaint.parser.JavaParserService#parseDirectory}, which scopes
 * one to the JDK plus the directory being scanned), {@code call.resolve()} is tried first and,
 * on success, gives ground-truth class/overload resolution -- handles statics, generics and
 * inherited methods the heuristic below cannot. It very often can't resolve (missing classpath
 * jars, unresolved external/library types, or -- in every unit test in this codebase, and any
 * ad-hoc {@code StaticJavaParser.parse(String)} snippet -- no resolver configured at all), in
 * which case it throws and this silently falls through to the same purely syntactic resolution
 * this engine has always used ({@link com.thanh.springtaint.dfg.DfgBuilder} makes the identical
 * no-symbol-solver choice, unconditionally):
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
 * overloads are disambiguated only by argument count, not by type. These are the same
 * kind of deferred-precision trade-offs already made in CfgBuilder/DfgBuilder, to keep
 * the engine running end-to-end before tightening accuracy.
 *
 * Constructor calls ({@code new Foo(x)}) are tracked the same way method calls are: the
 * callee is keyed as {@code MethodKey(className, "<init>", argCount)}, mirroring the JVM's
 * own constructor-naming convention. A project-local class's own constructors are indexed
 * as callers too (so a constructor that itself calls something dangerous is visible), but
 * -- unlike method calls -- constructor resolution is never symbol-solved and never goes
 * through the interface/abstract dispatch fan-out above: {@code new Foo()} is never
 * polymorphic, it always constructs exactly the named type, so neither is needed.
 */
public class CallGraphBuilder {

    private static final String UNKNOWN_CLASS = "?";

    public CallGraph build(List<CompilationUnit> units) {
        Map<String, Map<String, String>> fieldTypesByClass = new HashMap<>();
        Map<String, List<String>> subtypesBySupertype = new HashMap<>();
        Set<MethodKey> declaredMethods = new LinkedHashSet<>();
        Map<MethodKey, MethodDeclaration> methodDeclarationsByKey = new HashMap<>();
        List<CallableDeclaration<?>> callables = new ArrayList<>();
        Map<CallableDeclaration<?>, String> classNameByCallable = new HashMap<>();

        for (CompilationUnit unit : units) {
            for (TypeDeclaration<?> typeDecl : unit.findAll(TypeDeclaration.class)) {
                String className = typeDecl.getNameAsString();
                fieldTypesByClass.put(className, fieldTypes(typeDecl));
                recordHierarchy(typeDecl, subtypesBySupertype);

                for (MethodDeclaration method : typeDecl.getMethods()) {
                    MethodKey key = new MethodKey(className, method.getNameAsString(), method.getParameters().size());
                    declaredMethods.add(key);
                    methodDeclarationsByKey.put(key, method);
                    callables.add(method);
                    classNameByCallable.put(method, className);
                }

                if (typeDecl instanceof ClassOrInterfaceDeclaration classOrInterface) {
                    for (ConstructorDeclaration constructor : classOrInterface.getConstructors()) {
                        MethodKey key = new MethodKey(className, MethodKey.CONSTRUCTOR_METHOD_NAME, constructor.getParameters().size());
                        declaredMethods.add(key);
                        callables.add(constructor);
                        classNameByCallable.put(constructor, className);
                    }
                }
            }
        }

        List<CallGraphEdge> edges = new ArrayList<>();
        for (CallableDeclaration<?> callable : callables) {
            String className = classNameByCallable.get(callable);
            String methodName = callable instanceof ConstructorDeclaration
                    ? MethodKey.CONSTRUCTOR_METHOD_NAME
                    : callable.getNameAsString();
            MethodKey caller = new MethodKey(className, methodName, callable.getParameters().size());
            Map<String, String> localTypes = localTypes(callable, fieldTypesByClass.get(className));

            for (MethodCallExpr call : callable.findAll(MethodCallExpr.class)) {
                MethodKey primary = resolveCallee(call, className, localTypes);
                for (MethodKey callee : resolveDispatchTargets(primary, declaredMethods, methodDeclarationsByKey,
                        subtypesBySupertype)) {
                    edges.add(new CallGraphEdge(caller, callee, call.toString()));
                }
            }
            for (ObjectCreationExpr newExpr : callable.findAll(ObjectCreationExpr.class)) {
                edges.add(new CallGraphEdge(caller, resolveConstructorCallee(newExpr), newExpr.toString()));
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

    private Map<String, String> localTypes(CallableDeclaration<?> callable, Map<String, String> fieldTypes) {
        Map<String, String> localTypes = new HashMap<>();
        if (fieldTypes != null) {
            localTypes.putAll(fieldTypes);
        }
        for (Parameter parameter : callable.getParameters()) {
            localTypes.put(parameter.getNameAsString(), simpleTypeName(parameter.getType().asString()));
        }
        for (VariableDeclarator variable : callable.findAll(VariableDeclarator.class)) {
            localTypes.put(variable.getNameAsString(), simpleTypeName(variable.getType().asString()));
        }
        return localTypes;
    }

    /**
     * {@code new Foo(a, b)} always constructs exactly {@code Foo} -- no dispatch ambiguity,
     * so (unlike {@link #resolveCallee}) this never needs symbol resolution or CHA fan-out.
     */
    private MethodKey resolveConstructorCallee(ObjectCreationExpr newExpr) {
        String className = simpleTypeName(newExpr.getType().asString());
        return new MethodKey(className, MethodKey.CONSTRUCTOR_METHOD_NAME, newExpr.getArguments().size());
    }

    private MethodKey resolveCallee(MethodCallExpr call, String callerClassName, Map<String, String> localTypes) {
        MethodKey symbolic = trySymbolicResolve(call);
        if (symbolic != null) {
            return symbolic;
        }

        String methodName = call.getNameAsString();
        int argCount = call.getArguments().size();

        String calleeClass = call.getScope()
                .map(scope -> resolveScopeClass(scope, callerClassName, localTypes))
                .orElse(callerClassName);
        return new MethodKey(calleeClass, methodName, argCount);
    }

    /**
     * Ground-truth resolution via a {@code JavaSymbolSolver}, when one was injected into this
     * call's {@code CompilationUnit} (see class javadoc). {@code null} means "couldn't resolve
     * this one" -- either no resolver is configured at all (every unit test snippet), or the
     * symbol genuinely can't be found (missing classpath jar, unresolved generic, ...); both
     * are expected, routine outcomes here, not errors, so the caller falls back to the
     * syntactic heuristic rather than this method throwing.
     *
     * Uses the resolved method's own declared parameter count (not the call site's argument
     * count) so varargs calls key the same way a method's own declaration is keyed elsewhere
     * in this class (by {@code method.getParameters().size()}).
     */
    private MethodKey trySymbolicResolve(MethodCallExpr call) {
        try {
            ResolvedMethodDeclaration resolved = call.resolve();
            String simpleClassName = simpleTypeName(resolved.declaringType().getQualifiedName());
            return new MethodKey(simpleClassName, resolved.getName(), resolved.getNumberOfParams());
        } catch (RuntimeException e) {
            return null;
        }
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
        if (scope.isObjectCreationExpr()) {
            // Chained construct-then-call, e.g. `new ObjectInputStream(in).readObject()`: the
            // constructed type is right there syntactically, no variable lookup needed.
            return simpleTypeName(scope.asObjectCreationExpr().getType().asString());
        }
        if (scope.isFieldAccessExpr()) {
            // A fully-qualified static call, e.g. `org.apache.commons.lang.StringEscapeUtils
            // .escapeHtml(x)`: JavaParser represents the package-qualified prefix as a chain of
            // FieldAccessExpr, so the direct scope's own simple name (the last segment before
            // the method call) IS the class name -- same "starts with an uppercase letter"
            // convention-based heuristic already used for NameExpr above, which also correctly
            // avoids misreading a genuine instance field access (e.g. `this.helper.run()`,
            // conventionally lowercase) as if it were a class name.
            String name = scope.asFieldAccessExpr().getNameAsString();
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
