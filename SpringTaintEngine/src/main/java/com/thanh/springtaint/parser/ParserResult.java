package com.thanh.springtaint.parser;

import com.github.javaparser.ast.CompilationUnit;

import java.nio.file.Path;

public class ParserResult {
    private final Path sourcePath;
    private final CompilationUnit compilationUnit;

    public ParserResult(Path sourcePath, CompilationUnit compilationUnit) {
        this.sourcePath = sourcePath;
        this.compilationUnit = compilationUnit;
    }

    public Path getSourcePath() {
        return sourcePath;
    }

    public CompilationUnit getCompilationUnit() {
        return compilationUnit;
    }
}
