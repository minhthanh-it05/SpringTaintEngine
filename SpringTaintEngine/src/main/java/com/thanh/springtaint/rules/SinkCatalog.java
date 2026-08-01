package com.thanh.springtaint.rules;

import com.thanh.springtaint.callgraph.MethodKey;

import java.util.List;
import java.util.Set;

/** Registry of known-dangerous method calls (taint Sinks). */
public class SinkCatalog {

    private final List<SinkRule> rules;

    public SinkCatalog(List<SinkRule> rules) {
        this.rules = List.copyOf(rules);
    }

    public static SinkCatalog defaults() {
        return new SinkCatalog(List.of(
                new SinkRule("Statement", "executeQuery", Set.of(0),
                        VulnerabilityType.SQL_INJECTION, "JDBC Statement.executeQuery(sql)"),
                new SinkRule("Statement", "executeUpdate", Set.of(0),
                        VulnerabilityType.SQL_INJECTION, "JDBC Statement.executeUpdate(sql)"),
                new SinkRule("Statement", "execute", Set.of(0),
                        VulnerabilityType.SQL_INJECTION, "JDBC Statement.execute(sql)"),
                new SinkRule("Connection", "prepareStatement", Set.of(0),
                        VulnerabilityType.SQL_INJECTION, "JDBC Connection.prepareStatement(sql)"),
                new SinkRule(null, "exec", Set.of(0),
                        VulnerabilityType.COMMAND_INJECTION, "Runtime.exec(command)")
        ));
    }

    public List<SinkRule> match(MethodKey callee) {
        return rules.stream().filter(rule -> rule.matches(callee)).toList();
    }

    public boolean isSink(MethodKey callee) {
        return !match(callee).isEmpty();
    }
}
