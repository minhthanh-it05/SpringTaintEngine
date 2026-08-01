package com.thanh.springtaint.parser;

import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class JavaParserService {

    static {
        // StaticJavaParser's default language level predates records (Java 14+), which are
        // the idiomatic modern Spring Boot shape for request/response DTOs -- without this,
        // parsing any file that uses one throws ParseProblemException before this engine ever
        // gets a chance to analyze it. Matches this project's own Java 21 compiler target.
        StaticJavaParser.getParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
    }

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

    public List<ParserResult> parseDirectory(Path directory) throws IOException {
        List<ParserResult> results = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(directory)) {
            List<Path> javaFiles = paths.filter(p -> p.toString().endsWith(".java")).toList();
            for (Path file : javaFiles) {
                results.add(parseFile(file));
            }
        }
        return results;
    }
}
