package com.thanh.springtaint.detect;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.thanh.springtaint.callgraph.MethodKey;
import com.thanh.springtaint.parser.JavaParserService;
import com.thanh.springtaint.parser.ParserResult;
import com.thanh.springtaint.rules.TaintRules;
import com.thanh.springtaint.rules.VulnerabilityType;
import com.thanh.springtaint.taint.TaintEngine;
import com.thanh.springtaint.taint.TaintFinding;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Classifies raw {@link TaintFinding}s from the {@link TaintEngine} (M8) into
 * report-ready {@link Vulnerability} records: a stable id, severity and CWE id (from
 * {@link VulnerabilityType}, M7), a human-readable message, and -- when scanning a real
 * project via {@link #scanProject} -- the source file and declaration line of both ends
 * of the finding.
 */
public class Detector {

    private final TaintRules rules;

    public Detector() {
        this(TaintRules.defaults());
    }

    public Detector(TaintRules rules) {
        this.rules = rules;
    }

    /** Scans compilation units with no known file association; {@code sourceFile}/{@code sinkFile} come back null. */
    public List<Vulnerability> scan(List<CompilationUnit> units) {
        return scan(units, Map.of());
    }

    public List<Vulnerability> scanProject(Path projectDirectory) throws IOException {
        return scanProject(new JavaParserService().parseDirectory(projectDirectory));
    }

    public List<Vulnerability> scanProject(List<ParserResult> parserResults) {
        Map<String, Path> fileByClassName = new HashMap<>();
        List<CompilationUnit> units = new ArrayList<>();
        for (ParserResult result : parserResults) {
            units.add(result.getCompilationUnit());
            for (TypeDeclaration<?> typeDecl : result.getCompilationUnit().findAll(TypeDeclaration.class)) {
                fileByClassName.putIfAbsent(typeDecl.getNameAsString(), result.getSourcePath());
            }
        }
        return scan(units, fileByClassName);
    }

    private List<Vulnerability> scan(List<CompilationUnit> units, Map<String, Path> fileByClassName) {
        TaintEngine engine = new TaintEngine(units, rules);
        List<TaintFinding> findings = engine.analyze();

        Map<VulnerabilityType, Integer> countByType = new EnumMap<>(VulnerabilityType.class);
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (TaintFinding finding : findings) {
            VulnerabilityType type = finding.sinkRule().vulnerabilityType();
            int number = countByType.merge(type, 1, Integer::sum);
            String id = type.name() + "-" + number;

            Location sourceLocation = locate(finding.sourceMethod(), engine, fileByClassName);
            Location sinkLocation = locate(finding.sinkMethod(), engine, fileByClassName);

            vulnerabilities.add(new Vulnerability(id, type, type.defaultSeverity(), type.cweId(),
                    type.displayName(), buildMessage(finding), finding.sourceMethod(), finding.source(),
                    sourceLocation.file(), sourceLocation.line(),
                    finding.sinkMethod(), finding.sinkCallSite(), sinkLocation.file(), sinkLocation.line(),
                    finding.path(), false));
        }

        return vulnerabilities;
    }

    private Location locate(MethodKey key, TaintEngine engine, Map<String, Path> fileByClassName) {
        CallableDeclaration<?> declaration = engine.methodDeclaration(key);
        int line = declaration != null && declaration.getBegin().isPresent() ? declaration.getBegin().get().line : -1;
        Path file = fileByClassName.get(key.className());
        return new Location(file == null ? null : file.toString(), line);
    }

    private record Location(String file, int line) {
    }

    private String buildMessage(TaintFinding finding) {
        return "Untrusted input from parameter '" + finding.source().parameterName()
                + "' (@" + finding.source().sourceAnnotation() + ") in " + finding.sourceMethod()
                + " flows into " + finding.sinkMethod() + " at `" + finding.sinkCallSite()
                + "` without sanitization.";
    }
}
