package com.thanh.springtaint.rules;

/** A Spring annotation that marks the method parameter it's attached to as attacker-controlled input. */
public record SourceRule(String annotationSimpleName, String description) {
}
