package com.thanh.springtaint;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.thanh.springtaint.baseline.Baseline;
import com.thanh.springtaint.callgraph.CallGraph;
import com.thanh.springtaint.callgraph.CallGraphBuilder;
import com.thanh.springtaint.callgraph.CallGraphEdge;
import com.thanh.springtaint.cfg.CfgBuilder;
import com.thanh.springtaint.cfg.CfgEdge;
import com.thanh.springtaint.cfg.CfgNode;
import com.thanh.springtaint.cfg.ControlFlowGraph;
import com.thanh.springtaint.detect.Detector;
import com.thanh.springtaint.detect.Vulnerability;
import com.thanh.springtaint.dfg.DataFlowGraph;
import com.thanh.springtaint.dfg.DfgBuilder;
import com.thanh.springtaint.dfg.DfgEdge;
import com.thanh.springtaint.dfg.DfgNode;
import com.thanh.springtaint.parser.JavaParserService;
import com.thanh.springtaint.parser.ParserResult;
import com.thanh.springtaint.report.ConsoleReporter;
import com.thanh.springtaint.report.JsonReporter;
import com.thanh.springtaint.report.Reporter;
import com.thanh.springtaint.report.SarifReporter;
import com.thanh.springtaint.rules.Severity;
import com.thanh.springtaint.rules.TaintRules;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Command-line entry point: scans a Spring Boot project directory for taint-flow
 * vulnerabilities (@RequestParam/@RequestBody/... reaching a JDBC/exec/SSRF/... sink without
 * sanitization) and reports them in one or more formats.
 *
 * Usage:
 *   java -jar SpringTaintEngine.jar [project-dir] [options]
 *
 * Options:
 *   --format=console,json,sarif   comma-separated output formats (default: console)
 *   --out=&lt;path-prefix&gt;           output file prefix for json/sarif (default: taint-report)
 *   --fail-on-findings             exit with a non-zero status if any HIGH/CRITICAL finding
 *                                   is reported -- for CI gating; off by default so a bare
 *                                   report-and-inspect run never breaks a script. Findings
 *                                   present in the baseline never count toward this.
 *   --baseline=&lt;path&gt;              mark findings already present in this baseline file as
 *                                   suppressed (see {@link Baseline}) -- still shown in every
 *                                   report, just excluded from --fail-on-findings
 *   --write-baseline=&lt;path&gt;        write every finding from this run to the baseline file,
 *                                   overwriting it -- the "accept everything currently found"
 *                                   action, typically run once and the result committed
 *   --debug                        also dump structure/CFG/DFG/call graph internals for
 *                                   every parsed method (the M1-M6 milestone-inspection view)
 *   --help
 */
public class
Main {

    public static void main(String[] args) throws IOException {
        if (containsHelp(args)) {
            printUsage();
            return;
        }

        Path projectDir = Path.of("src/main/resources/samples");
        Set<String> formats = new LinkedHashSet<>();
        String outPrefix = "taint-report";
        boolean failOnFindings = false;
        boolean debug = false;
        Path baselinePath = null;
        Path writeBaselinePath = null;

        for (String arg : args) {
            if (arg.startsWith("--format=")) {
                formats.addAll(List.of(arg.substring("--format=".length()).split(",")));
            } else if (arg.startsWith("--out=")) {
                outPrefix = arg.substring("--out=".length());
            } else if (arg.equals("--fail-on-findings")) {
                failOnFindings = true;
            } else if (arg.startsWith("--baseline=")) {
                baselinePath = Path.of(arg.substring("--baseline=".length()));
            } else if (arg.startsWith("--write-baseline=")) {
                writeBaselinePath = Path.of(arg.substring("--write-baseline=".length()));
            } else if (arg.equals("--debug")) {
                debug = true;
            } else if (arg.startsWith("--")) {
                System.err.println("Unknown option: " + arg + " (see --help)");
            } else {
                projectDir = Path.of(arg);
            }
        }
        if (formats.isEmpty()) {
            formats.add("console");
        }

        JavaParserService parserService = new JavaParserService();
        List<ParserResult> projectFiles = parserService.parseDirectory(projectDir);
        System.out.println("Scanning " + projectFiles.size() + " file(s) in " + projectDir.toAbsolutePath());

        if (debug) {
            printDebugInternals(projectFiles);
        }

        TaintRules taintRules = TaintRules.defaults();
        List<Vulnerability> vulnerabilities = new Detector(taintRules).scanProject(projectFiles);

        if (writeBaselinePath != null) {
            Baseline.write(writeBaselinePath, vulnerabilities);
            System.out.println("Baseline written to: " + writeBaselinePath.toAbsolutePath()
                    + " (" + vulnerabilities.size() + " finding(s))");
        }

        if (baselinePath != null) {
            Baseline baseline = Baseline.load(baselinePath);
            vulnerabilities = vulnerabilities.stream()
                    .map(v -> baseline.contains(v) ? v.asSuppressed() : v)
                    .toList();
            System.out.println("Loaded baseline from: " + baselinePath.toAbsolutePath()
                    + " (" + baseline.size() + " known finding(s))");
        }

        for (String format : formats) {
            switch (format) {
                case "console" -> System.out.print(new ConsoleReporter().render(vulnerabilities));
                case "json" -> writeReport(new JsonReporter(), vulnerabilities, outPrefix + ".json");
                case "sarif" -> writeReport(new SarifReporter(), vulnerabilities, outPrefix + ".sarif");
                default -> System.err.println("Unknown format: " + format + " (expected console, json, sarif)");
            }
        }

        boolean hasSeriousFinding = vulnerabilities.stream()
                .filter(v -> !v.suppressed())
                .anyMatch(v -> v.severity() == Severity.HIGH || v.severity() == Severity.CRITICAL);
        if (failOnFindings && hasSeriousFinding) {
            System.exit(1);
        }
    }

    private static void writeReport(Reporter reporter, List<Vulnerability> vulnerabilities, String path)
            throws IOException {
        Files.writeString(Path.of(path), reporter.render(vulnerabilities));
        System.out.println("Report written to: " + Path.of(path).toAbsolutePath());
    }

    /** The M1-M6 milestone-inspection view: structure/CFG/DFG per method, plus the whole-project call graph. */
    private static void printDebugInternals(List<ParserResult> projectFiles) {
        CallGraph callGraph = new CallGraphBuilder()
                .build(projectFiles.stream().map(ParserResult::getCompilationUnit).toList());

        for (ParserResult result : projectFiles) {
            CompilationUnit unit = result.getCompilationUnit();
            for (MethodDeclaration methodDeclaration : unit.findAll(MethodDeclaration.class)) {
                ControlFlowGraph cfg = new CfgBuilder().build(methodDeclaration);
                System.out.println("CFG for " + result.getSourcePath() + "#" + methodDeclaration.getNameAsString() + ":");
                for (CfgEdge edge : cfg.edges()) {
                    System.out.println("  " + describe(edge.from()) + " -> " + describe(edge.to()) + labelOf(edge.label()));
                }

                DataFlowGraph dfg = new DfgBuilder().build(methodDeclaration);
                System.out.println("DFG for " + result.getSourcePath() + "#" + methodDeclaration.getNameAsString() + ":");
                for (DfgEdge edge : dfg.edges()) {
                    System.out.println("  " + describe(edge.from()) + " -> " + describe(edge.to()) + labelOf(edge.label()));
                }
            }
        }

        System.out.println("Call graph:");
        for (CallGraphEdge edge : callGraph.edges()) {
            String marker = callGraph.isExternal(edge.callee()) ? " [external]" : "";
            System.out.println("  " + edge.caller() + " -> " + edge.callee() + marker);
        }
        System.out.println();
    }

    private static String labelOf(String label) {
        return label == null ? "" : " [" + label + "]";
    }

    private static String describe(CfgNode node) {
        return "#" + node.id() + " " + node.kind() + (node.label() == null ? "" : ": " + node.label());
    }

    private static String describe(DfgNode node) {
        return "#" + node.id() + " " + node.kind()
                + (node.variableName() == null ? "" : " (" + node.variableName() + ")")
                + (node.label() == null ? "" : ": " + node.label());
    }

    private static boolean containsHelp(String[] args) {
        for (String arg : args) {
            if (arg.equals("--help") || arg.equals("-h")) {
                return true;
            }
        }
        return false;
    }

    private static void printUsage() {
        System.out.println("""
                SpringTaintEngine - self-implemented Java/Spring Boot taint analysis engine

                Usage:
                  java -jar SpringTaintEngine.jar [project-dir] [options]

                Arguments:
                  project-dir             Directory to scan (default: src/main/resources/samples)

                Options:
                  --format=<f1,f2,...>    Output formats: console, json, sarif (default: console)
                  --out=<prefix>          Output file prefix for json/sarif (default: taint-report)
                  --fail-on-findings      Exit with status 1 if any HIGH/CRITICAL finding is reported
                                          (findings in the baseline never count toward this)
                  --baseline=<path>       Mark findings already in this file as suppressed
                  --write-baseline=<path> Write every finding from this run to the baseline file
                  --debug                 Also dump structure/CFG/DFG/call graph internals
                  --help, -h              Show this message
                """);
    }
}
