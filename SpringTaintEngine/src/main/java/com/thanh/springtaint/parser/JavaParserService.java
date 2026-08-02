package com.thanh.springtaint.parser;

import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;

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

        // Best-effort symbol resolution, scoped to this one directory: JDK types via
        // reflection (always available) plus every type declared under `directory` itself
        // (covers the common case CallGraphBuilder's syntactic heuristic struggles with most --
        // an interface field resolving to its sibling implementation file). Types from
        // anything else (Spring, a library on some external classpath we were never given)
        // simply fail to resolve and CallGraphBuilder falls back to its syntactic heuristic --
        // this is deliberately best-effort, not a hard requirement for the engine to run.
        CombinedTypeSolver typeSolver = new CombinedTypeSolver();
        typeSolver.add(new ReflectionTypeSolver());
        typeSolver.add(new JavaParserTypeSolver(directory));
        JavaSymbolSolver symbolSolver = new JavaSymbolSolver(typeSolver);
        for (ParserResult result : results) {
            symbolSolver.inject(result.getCompilationUnit());
        }

        return results;
    }
}
