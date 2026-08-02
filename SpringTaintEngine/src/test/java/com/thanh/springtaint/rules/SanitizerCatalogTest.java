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
}
