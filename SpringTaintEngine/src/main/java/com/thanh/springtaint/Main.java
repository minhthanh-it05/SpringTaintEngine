package com.thanh.springtaint;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.thanh.springtaint.cfg.CfgBuilder;
import com.thanh.springtaint.cfg.CfgEdge;
import com.thanh.springtaint.cfg.ControlFlowGraph;
import com.thanh.springtaint.parser.JavaParserService;
import com.thanh.springtaint.parser.ParserResult;
import com.thanh.springtaint.structure.ClassInfo;
import com.thanh.springtaint.structure.MethodInfo;
import com.thanh.springtaint.structure.ParameterInfo;
import com.thanh.springtaint.structure.StructureAnalyzer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public class Main {
    public static void main(String[] args) throws IOException {
        Path filePath = args.length > 0
                ? Path.of(args[0])
                : Path.of("src/main/resources/samples/SampleController.java");

        JavaParserService parserService = new JavaParserService();
        ParserResult result = parserService.parseFile(filePath);

        System.out.println("Parsed file: " + result.getSourcePath());

        List<ClassInfo> classes = new StructureAnalyzer().analyze(result.getCompilationUnit());
        for (ClassInfo classInfo : classes) {
            System.out.println("class " + classInfo.name() + " " + classInfo.annotations());
            for (MethodInfo method : classInfo.methods()) {
                System.out.println("  method " + method.returnType() + " " + method.name() + " " + method.annotations());
                for (ParameterInfo parameter : method.parameters()) {
                    System.out.println("    param " + parameter.type() + " " + parameter.name() + " " + parameter.annotations());
                }
            }
        }

        List<MethodDeclaration> methodDeclarations = result.getCompilationUnit().findAll(MethodDeclaration.class);
        for (MethodDeclaration methodDeclaration : methodDeclarations) {
            ControlFlowGraph cfg = new CfgBuilder().build(methodDeclaration);
            System.out.println("CFG for method " + methodDeclaration.getNameAsString() + ":");
            for (CfgEdge edge : cfg.edges()) {
                String label = edge.label() == null ? "" : " [" + edge.label() + "]";
                System.out.println("  " + describe(edge.from()) + " -> " + describe(edge.to()) + label);
            }
        }
    }

    private static String describe(com.thanh.springtaint.cfg.CfgNode node) {
        return "#" + node.id() + " " + node.kind() + (node.label() == null ? "" : ": " + node.label());
    }

}

