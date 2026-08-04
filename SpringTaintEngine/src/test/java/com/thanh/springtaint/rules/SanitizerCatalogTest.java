package com.thanh.springtaint.rules;

import com.thanh.springtaint.callgraph.MethodKey;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SanitizerCatalogTest {

    @Test
    void sanitizes_matchesIntegerParseIntOnArgumentZero() {
        SanitizerCatalog catalog = SanitizerCatalog.defaults();

        assertTrue(catalog.sanitizes(new MethodKey("Integer", "parseInt", 1), 0));
    }

    @Test
    void sanitizes_doesNotMatchAnUnrelatedArgumentIndex() {
        SanitizerCatalog catalog = SanitizerCatalog.defaults();

        assertFalse(catalog.sanitizes(new MethodKey("Integer", "parseInt", 1), 1));
    }

    @Test
    void sanitizes_doesNotMatchAnUnrelatedMethod() {
        SanitizerCatalog catalog = SanitizerCatalog.defaults();

        assertFalse(catalog.sanitizes(new MethodKey("Statement", "executeQuery", 1), 0));
    }

    @Test
    void sanitizes_matchesApacheCommonsAndJsoupEscapingHelpers() {
        SanitizerCatalog catalog = SanitizerCatalog.defaults();

        assertTrue(catalog.sanitizes(new MethodKey("StringEscapeUtils", "escapeHtml4", 1), 0));
        assertTrue(catalog.sanitizes(new MethodKey("StringEscapeUtils", "escapeSql", 1), 0));
        assertTrue(catalog.sanitizes(new MethodKey("Jsoup", "clean", 2), 0));
    }

    @Test
    void sanitizes_matchesPre3xApacheCommonsLangEscapeHtmlWithoutTheFourSuffix() {
        // Legacy org.apache.commons.lang.StringEscapeUtils.escapeHtml (no "4" suffix, distinct
        // from the commons-lang3 escapeHtml4 above) -- still shows up in real/legacy code.
        SanitizerCatalog catalog = SanitizerCatalog.defaults();

        assertTrue(catalog.sanitizes(new MethodKey("StringEscapeUtils", "escapeHtml", 1), 0));
    }

    @Test
    void sanitizes_matchesFilenameUtilsGetNameAndUuidFromString() {
        SanitizerCatalog catalog = SanitizerCatalog.defaults();

        assertTrue(catalog.sanitizes(new MethodKey("FilenameUtils", "getName", 1), 0));
        assertTrue(catalog.sanitizes(new MethodKey("UUID", "fromString", 1), 0));
    }

    @Test
    void sanitizes_doesNotTreatPathsGetAsASanitizer() {
        // Paths.get(...) parses a string into a Path but does NOT strip ".." traversal
        // segments -- it must never be treated as neutralizing Path Traversal taint.
        SanitizerCatalog catalog = SanitizerCatalog.defaults();

        assertFalse(catalog.sanitizes(new MethodKey("Paths", "get", 1), 0));
    }
}
