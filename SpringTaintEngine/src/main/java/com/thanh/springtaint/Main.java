package com.thanh.springtaint;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.thanh.springtaint.callgraph.CallGraph;
import com.thanh.springtaint.callgraph.CallGraphBuilder;
import com.thanh.springtaint.callgraph.CallGraphEdge;
import com.thanh.springtaint.cfg.CfgBuilder;
import com.thanh.springtaint.cfg.CfgEdge;
import com.thanh.springtaint.cfg.ControlFlowGraph;
import com.thanh.springtaint.dfg.DataFlowGraph;
import com.thanh.springtaint.dfg.DfgBuilder;
import com.thanh.springtaint.dfg.DfgEdge;
import com.thanh.springtaint.dfg.DfgNode;
import com.thanh.springtaint.detect.Detector;
import com.thanh.springtaint.detect.Vulnerability;
import com.thanh.springtaint.parser.JavaParserService;
import com.thanh.springtaint.parser.ParserResult;
import com.thanh.springtaint.report.ConsoleReporter;
import com.thanh.springtaint.report.JsonReporter;
import com.thanh.springtaint.rules.TaintRules;
import com.thanh.springtaint.rules.TaintedParameter;
import com.thanh.springtaint.structure.ClassInfo;
import com.thanh.springtaint.structure.MethodInfo;
import com.thanh.springtaint.structure.ParameterInfo;
import com.thanh.springtaint.structure.StructureAnalyzer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class Main {
    public static void main(String[] args) throws IOException {
        Path filePath = args.length > 0
                ? Path.of(args[0])
                : Path.of("src/main/resources/samples/SampleController.java");

        JavaParserService parserService = new JavaParserService();
        ParserResult result = parserService.parseFile(filePath);
        TaintRules taintRules = TaintRules.defaults();

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

            DataFlowGraph dfg = new DfgBuilder().build(methodDeclaration);
            System.out.println("DFG for method " + methodDeclaration.getNameAsString() + ":");
            for (DfgEdge edge : dfg.edges()) {
                String label = edge.label() == null ? "" : " [" + edge.label() + "]";
                System.out.println("  " + describe(edge.from()) + " -> " + describe(edge.to()) + label);
            }

            List<TaintedParameter> sources = taintRules.sources().findSources(methodDeclaration);
            System.out.println("Sources in " + methodDeclaration.getNameAsString() + ": " + sources);
        }

        Path samplesDir = Path.of("src/main/resources/samples");
        List<ParserResult> projectFiles = parserService.parseDirectory(samplesDir);
        List<CompilationUnit> units = projectFiles.stream().map(ParserResult::getCompilationUnit).toList();
        CallGraph callGraph = new CallGraphBuilder().build(units);

        System.out.println("Call graph (" + samplesDir + "):");
        for (CallGraphEdge edge : callGraph.edges()) {
            String marker = callGraph.isExternal(edge.callee()) ? " [external]" : "";
            System.out.println("  " + edge.caller() + " -> " + edge.callee() + marker);
        }

        List<Vulnerability> vulnerabilities = new Detector(taintRules).scanProject(projectFiles);

        System.out.println();
        System.out.print(new ConsoleReporter().render(vulnerabilities));

        String json = new JsonReporter().render(vulnerabilities);
        Path reportPath = Path.of("taint-report.json");
        Files.writeString(reportPath, json);
        System.out.println("JSON report written to: " + reportPath.toAbsolutePath());
    }

    private static String describe(com.thanh.springtaint.cfg.CfgNode node) {
        return "#" + node.id() + " " + node.kind() + (node.label() == null ? "" : ": " + node.label());
    }

    private static String describe(DfgNode node) {
        return "#" + node.id() + " " + node.kind()
                + (node.variableName() == null ? "" : " (" + node.variableName() + ")")
                + (node.label() == null ? "" : ": " + node.label());
    }

}

