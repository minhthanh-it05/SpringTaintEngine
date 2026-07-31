package com.thanh.springtaint.structure;

import com.github.javaparser.ast.CompilationUnit;

import java.util.ArrayList;
import java.util.List;

public class StructureAnalyzer {

    public List<ClassInfo> analyze(CompilationUnit compilationUnit) {
        List<ClassInfo> classes = new ArrayList<>();
        new StructureVisitor().visit(compilationUnit, classes);
        return classes;
    }
}
