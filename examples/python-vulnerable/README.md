# Python demonstration project

This project intentionally pins old Python packages so that Dependency Watcher
can demonstrate real OSV.dev findings. Vulnerability results are not stored in
this repository; run the scanner to retrieve current data.

```bash
python cli/dw.py scan examples/python-vulnerable --no-registry
```

`click>=7.0` is intentionally unpinned and should be reported as UNKNOWN rather
than SAFE because exact version matching is impossible.
