# Rust demonstration project

Pinned crates are intentionally old so the scanner can query real OSV.dev data:

- `time@0.1.44`
- `smallvec@1.6.0`
- `regex@1.4.0`
- `rustc-serialize@0.3.24`

```bash
python cli/dw.py scan examples/rust-vulnerable --no-registry
```

No lockfile is included. The scanner reports the direct dependencies declared in
`Cargo.toml` and marks their exact versions as pinned.
