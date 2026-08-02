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
                        VulnerabilityType.INSECURE_DESERIALIZATION, "readObject() on an attacker-controlled stream"),

                // Opening a stream directly on an attacker-controlled path is the far more
                // common real-world Path Traversal shape than Files.newInputStream/readAllBytes
                // above -- these are constructor calls (methodName "<init>", see MethodKey /
                // CallGraphBuilder / DfgBuilder's ObjectCreationExpr handling).
                new SinkRule("FileInputStream", MethodKey.CONSTRUCTOR_METHOD_NAME, Set.of(0),
                        VulnerabilityType.PATH_TRAVERSAL, "new FileInputStream(path)"),
                new SinkRule("FileOutputStream", MethodKey.CONSTRUCTOR_METHOD_NAME, Set.of(0),
                        VulnerabilityType.PATH_TRAVERSAL, "new FileOutputStream(path)"),
                new SinkRule("FileReader", MethodKey.CONSTRUCTOR_METHOD_NAME, Set.of(0),
                        VulnerabilityType.PATH_TRAVERSAL, "new FileReader(path)"),
                new SinkRule("FileWriter", MethodKey.CONSTRUCTOR_METHOD_NAME, Set.of(0),
                        VulnerabilityType.PATH_TRAVERSAL, "new FileWriter(path)"),

                // Spring's own JdbcTemplate -- the standard, idiomatic way real Spring Boot
                // code talks to a database (far more common than raw java.sql.Statement above).
                // Every one of these methods takes the SQL string as its first argument.
                // Discovered missing by validating this engine against a real deliberately-
                // vulnerable Spring Boot project (malikashish8/vuln-spring): its SQL Injection
                // used exactly this API and this engine initially missed it entirely.
                new SinkRule("JdbcTemplate", "queryForMap", Set.of(0),
                        VulnerabilityType.SQL_INJECTION, "JdbcTemplate.queryForMap(sql)"),
                new SinkRule("JdbcTemplate", "queryForObject", Set.of(0),
                        VulnerabilityType.SQL_INJECTION, "JdbcTemplate.queryForObject(sql)"),
                new SinkRule("JdbcTemplate", "queryForList", Set.of(0),
                        VulnerabilityType.SQL_INJECTION, "JdbcTemplate.queryForList(sql)"),
                new SinkRule("JdbcTemplate", "query", Set.of(0),
                        VulnerabilityType.SQL_INJECTION, "JdbcTemplate.query(sql)"),
                new SinkRule("JdbcTemplate", "update", Set.of(0),
                        VulnerabilityType.SQL_INJECTION, "JdbcTemplate.update(sql)"),
                new SinkRule("JdbcTemplate", "execute", Set.of(0),
                        VulnerabilityType.SQL_INJECTION, "JdbcTemplate.execute(sql)"),

                // java.net.URL is the JDK's own pre-RestTemplate SSRF shape: the danger is the
                // receiver (built from an attacker-controlled URL string), not an argument --
                // same RECEIVER_INDEX mechanism as the deserialization sink above. Also found
                // missing via the same real-project validation.
                new SinkRule("URL", "openStream", Set.of(SinkRule.RECEIVER_INDEX),
                        VulnerabilityType.SSRF, "new URL(url).openStream()"),
                new SinkRule("URL", "openConnection", Set.of(SinkRule.RECEIVER_INDEX),
                        VulnerabilityType.SSRF, "new URL(url).openConnection()")
        ));
    }

    public List<SinkRule> match(MethodKey callee) {
        return rules.stream().filter(rule -> rule.matches(callee)).toList();
    }

    public boolean isSink(MethodKey callee) {
        return !match(callee).isEmpty();
    }
}
