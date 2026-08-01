package com.thanh.springtaint.rules;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.AnnotationExpr;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Registry of Spring annotations that mark a method parameter as untrusted,
 * attacker-controlled input -- a taint Source.
 */
public class SourceCatalog {

    private final Set<String> sourceAnnotations;

    public SourceCatalog(List<SourceRule> rules) {
        this.sourceAnnotations = rules.stream()
                .map(SourceRule::annotationSimpleName)
                .collect(Collectors.toUnmodifiableSet());
    }

    public static SourceCatalog defaults() {
        return new SourceCatalog(List.of(
                new SourceRule("RequestParam", "Query string / form parameter"),
                new SourceRule("PathVariable", "URI template variable"),
                new SourceRule("RequestBody", "Deserialized HTTP request body")
        ));
    }

    public boolean isSourceAnnotation(String annotationSimpleName) {
        return sourceAnnotations.contains(annotationSimpleName);
    }

    /** Parameters of {@code method} annotated with a registered Source annotation, in declaration order. */
    public List<TaintedParameter> findSources(MethodDeclaration method) {
        List<TaintedParameter> sources = new ArrayList<>();
        List<Parameter> parameters = method.getParameters();
        for (int i = 0; i < parameters.size(); i++) {
            Parameter parameter = parameters.get(i);
            for (AnnotationExpr annotation : parameter.getAnnotations()) {
                String name = annotation.getName().asString();
                if (isSourceAnnotation(name)) {
                    sources.add(new TaintedParameter(i, parameter.getNameAsString(), name));
                    break;
                }
            }
        }
        return sources;
    }
}
