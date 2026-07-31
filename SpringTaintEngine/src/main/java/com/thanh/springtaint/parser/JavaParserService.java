package com.thanh.springtaint.parser;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;

import java.io.IOException;
import java.nio.file.Path;

public class JavaParserService {

    private final JavaSourceLoader sourceLoader;

    public JavaParserService() {
        this(new JavaSourceLoader());
    }

    public JavaParserService(JavaSourceLoader sourceLoader) {
        this.sourceLoader = sourceLoader;
    }

    public CompilationUnit parse(String sourceCode) {
        return StaticJavaParser.parse(sourceCode);
    }

    public ParserResult parseFile(Path filePath) throws IOException {
        String sourceCode = sourceLoader.load(filePath);
        CompilationUnit compilationUnit = parse(sourceCode);
        return new ParserResult(filePath, compilationUnit);
    }
}
