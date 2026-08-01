package com.thanh.springtaint.report;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.thanh.springtaint.detect.Detector;
import com.thanh.springtaint.detect.Vulnerability;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonReporterTest {

    private static CompilationUnit sampleControllerUnit() {
        return StaticJavaParser.parse(
                "class SampleController { java.sql.Statement statement; "
                        + "String getUser(@RequestParam String id) throws Exception { "
                        + "  String query = \"SELECT * FROM users WHERE id = \" + id; "
                        + "  return statement.executeQuery(query).toString(); "
                        + "} }");
    }

    @Test
    void render_noFindings_producesValidlyBracketedEmptyReport() {
        String json = new JsonReporter().render(List.of());

        assertTrue(json.contains("\"findingCount\": 0"));
        assertEquals(count(json, '{'), count(json, '}'));
        assertEquals(count(json, '['), count(json, ']'));
    }

    @Test
    void render_withFindings_containsExpectedFieldsAndIsBraceBalanced() {
        List<Vulnerability> vulnerabilities = new Detector().scan(List.of(sampleControllerUnit()));

        String json = new JsonReporter().render(vulnerabilities);

        assertTrue(json.contains("\"findingCount\": 1"));
        assertTrue(json.contains("\"id\": \"SQL_INJECTION-1\""));
        assertTrue(json.contains("\"severity\": \"HIGH\""));
        assertTrue(json.contains("\"cweId\": \"CWE-89\""));
        assertTrue(json.contains("\"parameter\": \"id\""));
        assertTrue(json.contains("\"annotation\": \"RequestParam\""));
        assertTrue(json.contains("\"callSite\": \"statement.executeQuery(query)\""));
        // sink is JDK's Statement.executeQuery -- no declaration in the parsed source, so its line is unknown.
        assertTrue(json.contains("\"file\": null"));
        assertTrue(json.contains("\"line\": null"));
        assertEquals(count(json, '{'), count(json, '}'));
        assertEquals(count(json, '['), count(json, ']'));
    }

    @Test
    void render_escapesEmbeddedQuotesFromSourceLiteralsInPathLabels() {
        // The DFG label for the `query` assignment embeds the actual SQL string literal
        // (with its own double quotes) straight from the source -- if that isn't escaped
        // it silently breaks the JSON.
        List<Vulnerability> vulnerabilities = new Detector().scan(List.of(sampleControllerUnit()));

        String json = new JsonReporter().render(vulnerabilities);

        assertTrue(json.contains("\\\"SELECT"));
        assertEquals(count(json, '{'), count(json, '}'));
    }

    private static long count(String text, char c) {
        return text.chars().filter(ch -> ch == c).count();
    }
}
