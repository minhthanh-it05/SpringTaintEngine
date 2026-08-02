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
                        VulnerabilityType.COMMAND_INJECTION, "Runtime.exec(command)"),
                new SinkRule("RestTemplate", "getForObject", Set.of(0),
                        VulnerabilityType.SSRF, "RestTemplate.getForObject(url)"),
                new SinkRule("RestTemplate", "getForEntity", Set.of(0),
                        VulnerabilityType.SSRF, "RestTemplate.getForEntity(url)"),
                new SinkRule("RestTemplate", "postForObject", Set.of(0),
                        VulnerabilityType.SSRF, "RestTemplate.postForObject(url)"),
                new SinkRule("RestTemplate", "exchange", Set.of(0),
                        VulnerabilityType.SSRF, "RestTemplate.exchange(url)"),
                new SinkRule("Files", "newInputStream", Set.of(0),
                        VulnerabilityType.PATH_TRAVERSAL, "Files.newInputStream(path)"),
                new SinkRule("Files", "readAllBytes", Set.of(0),
                        VulnerabilityType.PATH_TRAVERSAL, "Files.readAllBytes(path)"),
                new SinkRule("PrintWriter", "print", Set.of(0),
                        VulnerabilityType.CROSS_SITE_SCRIPTING, "PrintWriter.print(value) into an HTTP response"),
                new SinkRule("PrintWriter", "println", Set.of(0),
                        VulnerabilityType.CROSS_SITE_SCRIPTING, "PrintWriter.println(value) into an HTTP response"),
                new SinkRule("ObjectInputStream", "readObject", Set.of(SinkRule.RECEIVER_INDEX),
                        VulnerabilityType.INSECURE_DESERIALIZATION, "readObject() on an attacker-controlled stream")
        ));
    }

    public List<SinkRule> match(MethodKey callee) {
        return rules.stream().filter(rule -> rule.matches(callee)).toList();
    }

    public boolean isSink(MethodKey callee) {
        return !match(callee).isEmpty();
    }
}
