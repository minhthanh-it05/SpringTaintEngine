package com.thanh.springtaint.rules;

/** Bundles the Source and Sink catalogs the taint engine is configured with. */
public record TaintRules(SourceCatalog sources, SinkCatalog sinks) {

    public static TaintRules defaults() {
        return new TaintRules(SourceCatalog.defaults(), SinkCatalog.defaults());
    }
}
