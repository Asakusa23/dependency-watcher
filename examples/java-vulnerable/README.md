# Java demonstration project

This Maven project pins old versions of Log4j, Jackson, Spring Core and Commons
Collections for real OSV.dev lookups. JUnit is scoped as a development (test)
dependency.

```bash
python cli/dw.py scan examples/java-vulnerable --no-registry
```

The property interpolation for `spring.version` is resolved by the Maven parser.
