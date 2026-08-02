package com.thanh.springtaint.report;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.thanh.springtaint.detect.Detector;
import com.thanh.springtaint.detect.Vulnerability;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SarifReporterTest {

    private static CompilationUnit sampleControllerUnit() {
        return StaticJavaParser.parse(
                "class SampleController { java.sql.Statement statement; "
                        + "String getUser(@RequestParam String id) throws Exception { "
                        + "  String query = \"SELECT * FROM users WHERE id = \" + id; "
                        + "  return statement.executeQuery(query).toString(); "
                        + "} }");
    }

    @Test
    void render_noFindings_producesAnEmptyResultsArrayAndIsBraceBalanced() {
        String sarif = new SarifReporter().render(List.of());

        assertTrue(sarif.contains("\"version\": \"2.1.0\""));
        assertTrue(sarif.contains("\"results\": [\n      ]") || sarif.contains("\"results\": [\n"));
        assertEquals(count(sarif, '{'), count(sarif, '}'));
        assertEquals(count(sarif, '['), count(sarif, ']'));
    }

    @Test
    void render_withFindings_containsOneRuleAndOneResultWithCweHelpUri() {
        List<Vulnerability> vulnerabilities = new Detector().scan(List.of(sampleControllerUnit()));

        String sarif = new SarifReporter().render(vulnerabilities);

        assertTrue(sarif.contains("\"id\": \"SQL_INJECTION\""));
        assertTrue(sarif.contains("\"ruleId\": \"SQL_INJECTION\""));
        assertTrue(sarif.contains("\"level\": \"error\""));
        assertTrue(sarif.contains("https://cwe.mitre.org/data/definitions/89.html"));
        assertEquals(count(sarif, '{'), count(sarif, '}'));
        assertEquals(count(sarif, '['), count(sarif, ']'));
    }

    @Test
    void render_rawCompilationUnitScan_omitsLocationsWhenNoFileIsKnown() {
        // Detector#scan (no ParserResult/file association) always leaves sinkFile null, and
        // here the sink is external JDK code so sourceFile is the only candidate -- but a raw
        // scan doesn't have one either, so no `locations` block should be emitted at all.
        List<Vulnerability> vulnerabilities = new Detector().scan(List.of(sampleControllerUnit()));

        String sarif = new SarifReporter().render(vulnerabilities);

        assertFalse(sarif.contains("\"locations\""));
    }

    @Test
    void render_projectScan_includesASourceFileLocationWhenTheSinkItselfHasNone() throws IOException {
        // Scanning a real project directory gives the SOURCE side a file/line even though the
        // sink (Statement.executeQuery, JDK code) never has one -- render should fall back to
        // the source location rather than silently dropping the location entirely.
        List<Vulnerability> vulnerabilities = new Detector().scanProject(Path.of("src/main/resources/samples"));
        Vulnerability finding = vulnerabilities.stream()
                .filter(v -> v.sourceMethod().className().equals("SampleController"))
                .findFirst().orElseThrow();

        String sarif = new SarifReporter().render(List.of(finding));

        assertTrue(sarif.contains("\"locations\""));
        assertTrue(sarif.contains("SampleController.java"));
        // artifact URIs are forward-slash, even though Path::toString on this project is OS-native.
        assertFalse(sarif.contains("samples\\\\SampleController.java"));
    }

    private static long count(String text, char c) {
        return text.chars().filter(ch -> ch == c).count();
    }
}
