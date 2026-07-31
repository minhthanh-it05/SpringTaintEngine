package com.thanh.springtaint.structure;

import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.List;

public class StructureVisitor extends VoidVisitorAdapter<List<ClassInfo>> {

    @Override
    public void visit(ClassOrInterfaceDeclaration classDecl, List<ClassInfo> collector) {
        super.visit(classDecl, collector);

        List<MethodInfo> methods = classDecl.getMethods().stream()
                .map(this::toMethodInfo)
                .toList();

        collector.add(new ClassInfo(
                classDecl.getNameAsString(),
                toAnnotationNames(classDecl.getAnnotations()),
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
