package com.thanh.springtaint.rules;

/** Bundles the Source, Sink and Sanitizer catalogs the taint engine is configured with. */
public record TaintRules(SourceCatalog sources, SinkCatalog sinks, SanitizerCatalog sanitizers) {

    public static TaintRules defaults() {
        return new TaintRules(SourceCatalog.defaults(), SinkCatalog.defaults(), SanitizerCatalog.defaults());
    }
}
