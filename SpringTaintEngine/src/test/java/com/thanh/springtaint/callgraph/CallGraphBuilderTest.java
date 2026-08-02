package com.thanh.springtaint.callgraph;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.thanh.springtaint.parser.JavaParserService;
import com.thanh.springtaint.parser.ParserResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CallGraphBuilderTest {

    @Test
    void build_implicitThisCall_resolvesToSameClass() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class Foo { void a() { b(); } void b() {} }");

        CallGraph graph = new CallGraphBuilder().build(List.of(unit));

        MethodKey caller = new MethodKey("Foo", "a", 0);
        MethodKey callee = new MethodKey("Foo", "b", 0);
        assertTrue(graph.edges().stream().anyMatch(e -> e.caller().equals(caller) && e.callee().equals(callee)));
        assertFalse(graph.isExternal(callee));
    }

    @Test
    void build_crossClassFieldTypedCall_resolvesAcrossCompilationUnits() {
        CompilationUnit controller = StaticJavaParser.parse(
                "class UserController { private UserService userService; "
                        + "String search(String name) { return userService.findByName(name); } }");
        CompilationUnit service = StaticJavaParser.parse(
                "class UserService { String findByName(String name) { return name; } }");

        CallGraph graph = new CallGraphBuilder().build(List.of(controller, service));

        MethodKey caller = new MethodKey("UserController", "search", 1);
        MethodKey callee = new MethodKey("UserService", "findByName", 1);
        assertTrue(graph.edges().stream().anyMatch(e -> e.caller().equals(caller) && e.callee().equals(callee)));
        assertFalse(graph.isExternal(callee));
    }

    @Test
    void build_callOnFieldOfUnparsedType_isRecordedAsExternal() {
        // No Statement class is parsed anywhere - this is exactly the JDBC sink shape.
        CompilationUnit unit = StaticJavaParser.parse(
                "class UserService { private java.sql.Statement statement; "
                        + "void run(String sql) throws Exception { statement.executeQuery(sql); } }");

        CallGraph graph = new CallGraphBuilder().build(List.of(unit));

        MethodKey callee = new MethodKey("Statement", "executeQuery", 1);
        assertTrue(graph.edges().stream().anyMatch(e -> e.callee().equals(callee)));
        assertTrue(graph.isExternal(callee));
    }

    @Test
    void build_staticStyleCallOnUnknownClass_usesIdentifierAsClassName() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class Foo { void run() { Runtime.getRuntime(); } }");

        CallGraph graph = new CallGraphBuilder().build(List.of(unit));

        MethodKey callee = new MethodKey("Runtime", "getRuntime", 0);
        assertTrue(graph.edges().stream().anyMatch(e -> e.callee().equals(callee)));
        assertTrue(graph.isExternal(callee));
    }

    @Test
    void build_chainedCallWithUnresolvableScope_marksCalleeClassUnknown() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class Foo { Object a() { return null; } void run() { a().toString(); } }");

        CallGraph graph = new CallGraphBuilder().build(List.of(unit));

        MethodKey callee = new MethodKey("?", "toString", 0);
        assertTrue(graph.edges().stream().anyMatch(e -> e.callee().equals(callee)));
    }

    @Test
    void build_interfaceDispatch_fansOutToConcreteImplementation() {
        // The common Spring shape: a field typed as an interface, injected with a concrete impl.
        CompilationUnit iface = StaticJavaParser.parse("interface UserService { String findByName(String name); }");
        CompilationUnit impl = StaticJavaParser.parse(
                "class UserServiceImpl implements UserService { "
                        + "public String findByName(String name) { return name; } }");
        CompilationUnit controller = StaticJavaParser.parse(
                "class UserController { private UserService userService; "
                        + "String search(String name) { return userService.findByName(name); } }");

        CallGraph graph = new CallGraphBuilder().build(List.of(iface, impl, controller));

        MethodKey caller = new MethodKey("UserController", "search", 1);
        MethodKey interfaceCallee = new MethodKey("UserService", "findByName", 1);
        MethodKey implCallee = new MethodKey("UserServiceImpl", "findByName", 1);

        // both the (body-less) interface edge and the concrete override edge are present
        assertTrue(graph.edges().stream().anyMatch(e -> e.caller().equals(caller) && e.callee().equals(interfaceCallee)));
        assertTrue(graph.edges().stream().anyMatch(e -> e.caller().equals(caller) && e.callee().equals(implCallee)));
        assertFalse(graph.isExternal(implCallee));
    }

    @Test
    void build_transitiveInterfaceDispatch_resolvesThroughAnAbstractIntermediateClass() {
        // interface -> abstract base (doesn't override) -> concrete class (does override)
        CompilationUnit iface = StaticJavaParser.parse("interface Repo { String find(String id); }");
        CompilationUnit abstractBase = StaticJavaParser.parse("abstract class AbstractRepo implements Repo { }");
        CompilationUnit concrete = StaticJavaParser.parse(
                "class SqlRepo extends AbstractRepo { public String find(String id) { return id; } }");
        CompilationUnit caller = StaticJavaParser.parse(
                "class Service { private Repo repo; String run(String id) { return repo.find(id); } }");

        CallGraph graph = new CallGraphBuilder().build(List.of(iface, abstractBase, concrete, caller));

        MethodKey callerKey = new MethodKey("Service", "run", 1);
        MethodKey concreteCallee = new MethodKey("SqlRepo", "find", 1);
        assertTrue(graph.edges().stream().anyMatch(e -> e.caller().equals(callerKey) && e.callee().equals(concreteCallee)));
        assertFalse(graph.isExternal(concreteCallee));
    }

    @Test
    void build_recordDeclaration_methodsAreIndexedAndCallable() {
        CompilationUnit unit = StaticJavaParser.parse(
                "record UserRequest(String name) { "
                        + "String process() { return helper(); } "
                        + "String helper() { return name; } }");

        CallGraph graph = new CallGraphBuilder().build(List.of(unit));

        MethodKey caller = new MethodKey("UserRequest", "process", 0);
        MethodKey callee = new MethodKey("UserRequest", "helper", 0);
        assertTrue(graph.edges().stream().anyMatch(e -> e.caller().equals(caller) && e.callee().equals(callee)));
        assertFalse(graph.isExternal(callee));
    }

    @Test
    void build_withSymbolResolverInjected_resolvesThroughAChainedCallTheSyntacticHeuristicCannot(
            @TempDir Path tempDir) throws IOException {
        // Same chained-call shape as build_chainedCallWithUnresolvableScope_marksCalleeClassUnknown
        // above (getter.getService().find(id): the scope of .find(...) is itself a method call,
        // not a typed variable), but this time scanned via JavaParserService#parseDirectory,
        // which injects a JavaSymbolSolver scoped to tempDir. Proves the symbol-solver-first
        // resolution in resolveCallee() actually resolves what the syntactic heuristic alone
        // cannot -- the "?" class from the other test becomes the real "Service" here.
        Files.writeString(tempDir.resolve("Getter.java"), "class Getter { Service getService() { return null; } }");
        Files.writeString(tempDir.resolve("Service.java"), "class Service { String find(String id) { return id; } }");
        Files.writeString(tempDir.resolve("Caller.java"),
                "class Caller { Getter getter; String run(String id) { return getter.getService().find(id); } }");

        List<CompilationUnit> units = new JavaParserService().parseDirectory(tempDir).stream()
                .map(ParserResult::getCompilationUnit)
                .toList();

        CallGraph graph = new CallGraphBuilder().build(units);

        MethodKey caller = new MethodKey("Caller", "run", 1);
        MethodKey callee = new MethodKey("Service", "find", 1);
        assertTrue(graph.edges().stream().anyMatch(e -> e.caller().equals(caller) && e.callee().equals(callee)));
        assertFalse(graph.isExternal(callee));
    }

    @Test
    void build_enumDeclaration_methodsAreIndexedAndCallable() {
        CompilationUnit unit = StaticJavaParser.parse(
                "enum Status { ACTIVE, INACTIVE; "
                        + "String label() { return describe(); } "
                        + "String describe() { return \"x\"; } }");

        CallGraph graph = new CallGraphBuilder().build(List.of(unit));

        MethodKey caller = new MethodKey("Status", "label", 0);
        MethodKey callee = new MethodKey("Status", "describe", 0);
        assertTrue(graph.edges().stream().anyMatch(e -> e.caller().equals(caller) && e.callee().equals(callee)));
        assertFalse(graph.isExternal(callee));
    }
}
