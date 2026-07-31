package com.thanh.springtaint.parser;

import com.github.javaparser.ParseProblemException;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JavaParserServiceTest {

    private static final Path SAMPLE_FILE = Path.of("src/main/resources/samples/SampleController.java");

    @Test
    void parseFile_returnsCompilationUnitWithExpectedClass() throws IOException {
        JavaParserService service = new JavaParserService();

        ParserResult result = service.parseFile(SAMPLE_FILE);

        assertEquals(SAMPLE_FILE, result.getSourcePath());

        CompilationUnit compilationUnit = result.getCompilationUnit();
        assertNotNull(compilationUnit);

        ClassOrInterfaceDeclaration sampleController = compilationUnit.getClassByName("SampleController")
                .orElseThrow(() -> new AssertionError("Class SampleController not found in AST"));

        assertEquals(1, sampleController.getMethods().size());
        assertEquals("getUser", sampleController.getMethods().get(0).getNameAsString());
    }

    @Test
    void parse_throwsOnInvalidSource() {
        JavaParserService service = new JavaParserService();

        assertThrows(ParseProblemException.class, () -> service.parse("this is not valid java"));
    }
}
