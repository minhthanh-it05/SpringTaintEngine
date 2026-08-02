# SpringTaintEngine

A self-implemented static taint-analysis engine for Java/Spring Boot code. Given a project's
source tree, it finds paths where untrusted input (`@RequestParam`, `@RequestBody`,
`@RequestHeader`, ...) reaches a dangerous sink (JDBC, `Runtime.exec`, `RestTemplate`,
deserialization, ...) without going through a recognized sanitizer, and reports each path as a
CWE-tagged finding with its full source-to-sink trace.

It is built directly on [JavaParser](https://github.com/javaparser/javaparser)'s AST — there is
no off-the-shelf SAST/dataflow library underneath. Every stage of the pipeline (control-flow
graph, data-flow graph, call graph, interprocedural taint propagation) is implemented in this
repository.

## Pipeline

```
source files
     |
     v
 AST (JavaParser)
     |
     v
 Structure (classes/methods/params + annotations)
     |
     v
 CFG  ---------------------\
     |                      |  per method
     v                      |
 DFG  <----------------------
     |
     v
 Call Graph  (whole project, interface/abstract dispatch via a simplified CHA)
     |
     v
 Taint Propagation  (interprocedural worklist reachability, source -> sink)
     |
     v
 Detector  (classify into CWE + severity)
     |
     v
 Report  (console / JSON / SARIF)
```

| Stage | Package | What it does |
|---|---|---|
| Parse | `parser` | Loads source files into JavaParser ASTs |
| Structure | `structure` | Extracts classes/methods/parameters and their annotations |
| CFG | `cfg` | Per-method control-flow graph (if/while/for/try-catch-finally) |
| DFG | `dfg` | Per-method data-flow graph: which values feed which variable/call/return |
| Call Graph | `callgraph` | Whole-project call graph, with interface/abstract dispatch fan-out |
| Rules | `rules` | Source / Sink / Sanitizer catalogs |
| Taint | `taint` | Interprocedural worklist reachability from source to sink |
| Detect | `detect` | Classifies raw findings into CWE/severity-tagged vulnerabilities |
| Report | `report` | Console, JSON, and SARIF 2.1.0 output |

## Detection coverage

| Vulnerability | CWE | Example sink |
|---|---|---|
| SQL Injection | CWE-89 | `Statement.executeQuery`, `Connection.prepareStatement` |
| Command Injection | CWE-78 | `Runtime.exec` |
| Server-Side Request Forgery | CWE-918 | `RestTemplate.getForObject/exchange` |
| Cross-Site Scripting | CWE-79 | `PrintWriter.print/println` |
| Path Traversal | CWE-22 | `Files.newInputStream/readAllBytes` |
| Insecure Deserialization | CWE-502 | `ObjectInputStream.readObject` |

Sources: `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`,
`@MatrixVariable`. Recognized sanitizers (taint-neutralizing calls): numeric coercion
(`Integer.parseInt`, ...), `HtmlUtils.htmlEscape`, `URLEncoder.encode`. All three catalogs
(`rules.SourceCatalog`, `rules.SinkCatalog`, `rules.SanitizerCatalog`) are plain data and easy
to extend.

## Build & run

```bash
mvn test              # run the test suite
mvn package            # produces target/SpringTaintEngine-*.jar (runnable, dependencies bundled)

java -jar target/SpringTaintEngine-*.jar <project-dir> [options]
```

If no argument is given, it scans the bundled sample project at
`src/main/resources/samples`.

### CLI options

```
--format=<f1,f2,...>    Output formats: console, json, sarif (default: console)
--out=<prefix>          Output file prefix for json/sarif (default: taint-report)
--fail-on-findings      Exit with status 1 if any HIGH/CRITICAL finding is reported (for CI)
--debug                 Also dump structure/CFG/DFG/call graph internals per method
--help, -h              Show usage
```

Example: scan a project and emit both a human-readable report and a SARIF file for GitHub
Code Scanning / VS Code's SARIF viewer:

```bash
java -jar target/SpringTaintEngine-*.jar path/to/your/spring-project \
    --format=console,sarif --out=target/taint-report --fail-on-findings
```

## Sample output

```
Taint analysis report - 4 finding(s)
============================================================
[SQL_INJECTION-1] HIGH - SQL Injection (CWE-89)
  Untrusted input from parameter 'id' (@RequestParam) in SampleController.getUser/2 flows into Statement.executeQuery/1 at `statement.executeQuery(query)` without sanitization.
  source: SampleController.getUser/2 (src/main/resources/samples/SampleController.java:12)
  sink:   Statement.executeQuery/1
  path:
    -> SampleController.getUser/2 #0 PARAM: id
    -> SampleController.getUser/2 #5 EXPRESSION: "SELECT * FROM users WHERE id = " + id
    -> SampleController.getUser/2 #4 ASSIGN: query = "SELECT * FROM users WHERE id = " + id
    -> SampleController.getUser/2 #8 CALL: statement.executeQuery(query)
```

## Design trade-offs

This engine deliberately favors **recall over precision** and getting the full pipeline
running end-to-end over exhaustive language coverage. The main, explicitly documented
trade-offs (see each class's Javadoc for the full reasoning):

- **No full symbol resolution by default.** Call/type resolution is mostly syntactic (matched
  by simple class name, not fully-qualified type). A best-effort `JavaSymbolSolver` is
  optionally wired in for whole-project scans (`JavaParserService#parseDirectory`) and used
  first when it can resolve a call; the syntactic heuristic is the fallback, not a replacement.
- **Flow-insensitive within a method.** if/while/try branches share one reaching-definition
  map with no per-branch merge at join points.
- **1-call-site-sensitive, not fully context-sensitive.** Taint returning from a callee jumps
  back to the exact call site it came from, but only one hop deep; beyond that it broadcasts
  to every call site of a method, same as a fully context-insensitive analysis would.
- **CHA-based dispatch, not points-to.** An interface/abstract call fans out to every concrete
  override found in the parsed sources rather than resolving the one actually injected at
  runtime — more recall, less precision, by design.

## Testing

```bash
mvn test
```

The test suite exercises every stage of the pipeline independently (CFG/DFG/call graph
builders, rule catalogs, the taint engine, each reporter) as well as end-to-end scenarios
against the bundled sample project.
