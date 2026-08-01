package com.thanh.springtaint.structure;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.thanh.springtaint.parser.JavaParserService;
import com.thanh.springtaint.parser.ParserResult;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StructureAnalyzerTest {

    private static final Path SAMPLE_FILE = Path.of("src/main/resources/samples/SampleController.java");

    @Test
    void analyze_extractsClassMethodAndParameterInfo() throws IOException {
        ParserResult parserResult = new JavaParserService().parseFile(SAMPLE_FILE);

        List<ClassInfo> classes = new StructureAnalyzer().analyze(parserResult.getCompilationUnit());

        assertEquals(1, classes.size());
        ClassInfo controller = classes.get(0);
        assertEquals("SampleController", controller.name());
        assertTrue(controller.annotations().contains("RestController"));

        assertEquals(1, controller.methods().size());
        MethodInfo getUser = controller.methods().get(0);
        assertEquals("getUser", getUser.name());
        assertEquals("String", getUser.returnType());
        assertTrue(getUser.annotations().contains("GetMapping"));

        assertEquals(2, getUser.parameters().size());

        ParameterInfo id = getUser.parameters().get(0);
        assertEquals("id", id.name());
        assertEquals("String", id.type());
        assertTrue(id.annotations().contains("RequestParam"));

        ParameterInfo statement = getUser.parameters().get(1);
        assertEquals("statement", statement.name());
        assertEquals("Statement", statement.type());
        assertTrue(statement.annotations().isEmpty());
    }

    @Test
    void analyze_recordDeclaration_isVisitedLikeAClass() {
        // Records are the idiomatic modern Spring Boot shape for request/response DTOs
        // (e.g. `record UserRequest(...)` used as an @RequestBody) -- before this fix the
        // visitor only handled ClassOrInterfaceDeclaration, so records were silently skipped.
        CompilationUnit unit = StaticJavaParser.parse(
                "record UserRequest(String name) { "
                        + "String process(@RequestParam String extra) { return name + extra; } }");

        List<ClassInfo> classes = new StructureAnalyzer().analyze(unit);

        assertEquals(1, classes.size());
        assertEquals("UserRequest", classes.get(0).name());
        assertEquals(1, classes.get(0).methods().size());
        assertEquals("process", classes.get(0).methods().get(0).name());
    }

    @Test
    void analyze_enumDeclaration_isVisitedLikeAClass() {
        CompilationUnit unit = StaticJavaParser.parse(
                "enum Status { ACTIVE, INACTIVE; String describe() { return name(); } }");

        List<ClassInfo> classes = new StructureAnalyzer().analyze(unit);

        assertEquals(1, classes.size());
        assertEquals("Status", classes.get(0).name());
        assertEquals(1, classes.get(0).methods().size());
    }
}
