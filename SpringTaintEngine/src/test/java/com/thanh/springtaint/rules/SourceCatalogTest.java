package com.thanh.springtaint.rules;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.body.MethodDeclaration;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SourceCatalogTest {

    @Test
    void isSourceAnnotation_recognizesDefaultSpringSourceAnnotations() {
        SourceCatalog catalog = SourceCatalog.defaults();

        assertTrue(catalog.isSourceAnnotation("RequestParam"));
        assertTrue(catalog.isSourceAnnotation("PathVariable"));
        assertTrue(catalog.isSourceAnnotation("RequestBody"));
        assertFalse(catalog.isSourceAnnotation("Autowired"));
    }

    @Test
    void findSources_onlyReturnsAnnotatedParameters_withCorrectIndex() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "String getUser(@RequestParam String id, java.sql.Statement statement) { return id; }");

        List<TaintedParameter> sources = SourceCatalog.defaults().findSources(method);

        assertEquals(1, sources.size());
        TaintedParameter source = sources.get(0);
        assertEquals(0, source.index());
        assertEquals("id", source.parameterName());
        assertEquals("RequestParam", source.sourceAnnotation());
    }

    @Test
    void findSources_multipleAnnotatedParameters_reportsEachWithItsOwnIndex() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration(
                "String get(@PathVariable String id, @RequestBody String body, int page) { return id; }");

        List<TaintedParameter> sources = SourceCatalog.defaults().findSources(method);

        assertEquals(2, sources.size());
        assertEquals(new TaintedParameter(0, "id", "PathVariable"), sources.get(0));
        assertEquals(new TaintedParameter(1, "body", "RequestBody"), sources.get(1));
    }
}
