package com.thanh.springtaint.structure;

import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.EnumDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.RecordDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.List;

/**
 * Visits every top-level "type with methods" JavaParser knows about -- classes,
 * interfaces, enums, and records (records especially matter: they're the idiomatic way
 * to write request/response DTOs in modern Spring Boot, e.g.
 * {@code record UserRequest(...)} used as an {@code @RequestBody}).
 */
public class StructureVisitor extends VoidVisitorAdapter<List<ClassInfo>> {

    @Override
    public void visit(ClassOrInterfaceDeclaration classDecl, List<ClassInfo> collector) {
        super.visit(classDecl, collector);
        addClassInfo(classDecl, collector);
    }

    @Override
    public void visit(EnumDeclaration enumDecl, List<ClassInfo> collector) {
        super.visit(enumDecl, collector);
        addClassInfo(enumDecl, collector);
    }

    @Override
    public void visit(RecordDeclaration recordDecl, List<ClassInfo> collector) {
        super.visit(recordDecl, collector);
        addClassInfo(recordDecl, collector);
    }

    private void addClassInfo(TypeDeclaration<?> typeDecl, List<ClassInfo> collector) {
        List<MethodInfo> methods = typeDecl.getMethods().stream()
                .map(this::toMethodInfo)
                .toList();

        collector.add(new ClassInfo(
                typeDecl.getNameAsString(),
                toAnnotationNames(typeDecl.getAnnotations()),
                methods));
    }

    private MethodInfo toMethodInfo(MethodDeclaration method) {
        List<ParameterInfo> parameters = method.getParameters().stream()
                .map(this::toParameterInfo)
                .toList();

        return new MethodInfo(
                method.getNameAsString(),
                method.getType().asString(),
                parameters,
                toAnnotationNames(method.getAnnotations()));
    }

    private ParameterInfo toParameterInfo(Parameter parameter) {
        return new ParameterInfo(
                parameter.getNameAsString(),
                parameter.getType().asString(),
                toAnnotationNames(parameter.getAnnotations()));
    }

    private List<String> toAnnotationNames(NodeList<AnnotationExpr> annotations) {
        return annotations.stream()
                .map(annotation -> annotation.getName().asString())
                .toList();
    }
}
