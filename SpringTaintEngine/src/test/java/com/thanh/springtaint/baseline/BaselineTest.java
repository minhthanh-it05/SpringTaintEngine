package com.thanh.springtaint.baseline;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.thanh.springtaint.detect.Detector;
import com.thanh.springtaint.detect.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BaselineTest {

    private static Vulnerability sqlInjection() {
        CompilationUnit unit = StaticJavaParser.parse(
                "class SampleController { java.sql.Statement statement; "
                        + "String getUser(@RequestParam String id) throws Exception { "
                        + "  String query = \"SELECT * FROM users WHERE id = \" + id; "
                        + "  return statement.executeQuery(query).toString(); "
                        + "} }");
        return new Detector().scan(List.of(unit)).get(0);
    }

    @Test
    void emptyBaseline_containsNothing() {
        Vulnerability vulnerability = sqlInjection();

        assertFalse(Baseline.empty().contains(vulnerability));
    }

    @Test
    void writeThenLoad_roundTripsAFindingsFingerprint(@TempDir Path tempDir) throws IOException {
        Vulnerability vulnerability = sqlInjection();
        Path baselineFile = tempDir.resolve("baseline.txt");

        Baseline.write(baselineFile, List.of(vulnerability));
        Baseline loaded = Baseline.load(baselineFile);

        assertTrue(loaded.contains(vulnerability));
        assertEquals(1, loaded.size());
    }

    @Test
    void load_ignoresCommentAndBlankLines(@TempDir Path tempDir) throws IOException {
        Vulnerability vulnerability = sqlInjection();
        Path baselineFile = tempDir.resolve("baseline.txt");
        Files.writeString(baselineFile,
                "# this is a header comment\n"
                        + "\n"
                        + "   \n"
                        + vulnerability.fingerprint() + "  SQL_INJECTION-1 SampleController.getUser/1 -> Statement.executeQuery/1\n"
                        + "# trailing comment\n");

        Baseline loaded = Baseline.load(baselineFile);

        assertTrue(loaded.contains(vulnerability));
        assertEquals(1, loaded.size());
    }

    @Test
    void contains_isFalseForAFindingNotInTheBaseline(@TempDir Path tempDir) throws IOException {
        Vulnerability inBaseline = sqlInjection();
        CompilationUnit otherUnit = StaticJavaParser.parse(
                "class Runner { void run(@RequestParam String cmd) { Runtime.getRuntime().exec(cmd); } }");
        Vulnerability notInBaseline = new Detector().scan(List.of(otherUnit)).get(0);
        Path baselineFile = tempDir.resolve("baseline.txt");
        Baseline.write(baselineFile, List.of(inBaseline));

        Baseline loaded = Baseline.load(baselineFile);

        assertTrue(loaded.contains(inBaseline));
        assertFalse(loaded.contains(notInBaseline));
    }

    @Test
    void write_producesAFileReadableAsPlainTextWithAHumanReadableComment(@TempDir Path tempDir) throws IOException {
        Vulnerability vulnerability = sqlInjection();
        Path baselineFile = tempDir.resolve("baseline.txt");

        Baseline.write(baselineFile, List.of(vulnerability));
        String content = Files.readString(baselineFile);

        assertTrue(content.contains(vulnerability.fingerprint()));
        assertTrue(content.contains("SQL_INJECTION-1"));
        assertTrue(content.contains("SampleController"));
    }
}
