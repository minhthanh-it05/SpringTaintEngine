package com.thanh.springtaint.parser;

import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JarTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
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
        // reflection (always available), every type declared under `directory` itself (covers
        // the common case CallGraphBuilder's syntactic heuristic struggles with most -- an
        // interface field resolving to its sibling implementation file), plus -- when
        // `directory` is a Maven project -- every dependency jar Maven itself reports on the
        // classpath (see resolveMavenDependencyJars). Types from anything we still don't have
        // (a non-Maven build, a jar Maven couldn't resolve) simply fail to resolve and
        // CallGraphBuilder falls back to its syntactic heuristic -- this is deliberately
        // best-effort, not a hard requirement for the engine to run.
        CombinedTypeSolver typeSolver = new CombinedTypeSolver();
        typeSolver.add(new ReflectionTypeSolver());
        typeSolver.add(new JavaParserTypeSolver(directory));
        List<Path> dependencyJars = resolveMavenDependencyJars(directory);
        for (Path jar : dependencyJars) {
            try {
                typeSolver.add(new JarTypeSolver(jar));
            } catch (IOException e) {
                System.err.println("Skipping unreadable dependency jar " + jar + ": " + e.getMessage());
            }
        }
        if (!dependencyJars.isEmpty()) {
            System.err.println("Resolved " + dependencyJars.size() + " Maven dependency jar(s) for symbol resolution");
        }
        JavaSymbolSolver symbolSolver = new JavaSymbolSolver(typeSolver);
        for (ParserResult result : results) {
            symbolSolver.inject(result.getCompilationUnit());
        }

        return results;
    }

    /**
     * Best-effort: when {@code directory} is a Maven project (has a {@code pom.xml}), asks
     * Maven itself for every dependency jar on its classpath via
     * {@code mvn dependency:build-classpath}, so symbol resolution above can see real library
     * types (Spring, JPA, ...) instead of leaving CallGraphBuilder to guess by simple-name
     * matching alone for every call into a library. This does not compile the project -- Maven
     * only needs to resolve the dependency tree, which is normally already cached locally after
     * the first build.
     *
     * Never throws: a missing {@code pom.xml}, a missing/failing {@code mvn} executable, or a
     * timeout all fall back to an empty list, same as before this method existed. A slow/absent
     * Maven should degrade resolution quality, not break the scan.
     */
    private List<Path> resolveMavenDependencyJars(Path directory) {
        Path pom = directory.resolve("pom.xml");
        if (!Files.isRegularFile(pom)) {
            return List.of();
        }

        Path outputFile;
        try {
            outputFile = Files.createTempFile("springtaint-classpath", ".txt");
        } catch (IOException e) {
            return List.of();
        }

        try {
            String mvnCommand = System.getProperty("os.name", "").toLowerCase().contains("win") ? "mvn.cmd" : "mvn";
            ProcessBuilder processBuilder = new ProcessBuilder(mvnCommand, "-q", "dependency:build-classpath",
                    "-Dmdep.outputFile=" + outputFile.toAbsolutePath());
            processBuilder.directory(directory.toFile());
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            // Drain stdout so Maven can't block on a full pipe buffer while we wait below.
            process.getInputStream().readAllBytes();

            boolean finished = process.waitFor(120, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                System.err.println("Maven classpath resolution timed out for " + directory
                        + "; continuing without external dependency jars");
                return List.of();
            }
            if (process.exitValue() != 0 || !Files.isRegularFile(outputFile)) {
                System.err.println("Maven classpath resolution failed for " + directory
                        + "; continuing without external dependency jars");
                return List.of();
            }

            String classpath = Files.readString(outputFile).strip();
            if (classpath.isEmpty()) {
                return List.of();
            }
            String separator = System.getProperty("path.separator", ":");
            return Arrays.stream(classpath.split(java.util.regex.Pattern.quote(separator)))
                    .filter(entry -> !entry.isBlank())
                    .map(Path::of)
                    .filter(Files::isRegularFile)
                    .toList();
        } catch (IOException e) {
            System.err.println("Maven not available while resolving classpath for " + directory
                    + "; continuing without external dependency jars (" + e.getMessage() + ")");
            return List.of();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return List.of();
        } finally {
            try {
                Files.deleteIfExists(outputFile);
            } catch (IOException ignored) {
                // best-effort cleanup of a temp file; leaving it behind is harmless
            }
        }
    }
}
