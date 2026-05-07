# Fixed Fuzz / Regression Artifacts

Each security-relevant crash or weird-input bug fixed in Mesh Infinity should
leave a committed reproducer here.

Expected layout:

```
fuzz/artifacts/fixed/
  YYYY-MM-DD-short-bug-name/
    input.bin
    README.md
```

Each per-bug `README.md` should explain:

- `Target: <fuzz_target_name>` on its own line so CI can replay the input
- what the input triggered
- which parser / state machine was affected
- whether the issue was security-relevant
- what regression test or corpus replay now covers it

This directory is for fixed regressions only, not for active crash artifacts.
