# Example reports

Generated with the built-in demo mode, so they can be reproduced without any setup:

```bash
aegis scan --target demo:vulnerable-chatbot --out demo-vulnerable.json
aegis report demo-vulnerable.json --format pdf -o demo-vulnerable.pdf
aegis scan --target demo:patched-chatbot --out demo-patched.json
```

- `demo-vulnerable.pdf` and `demo-vulnerable.json`: the vulnerable lab, 14 findings, score 0/100.
- `demo-patched.json`: the fixed variant, no finding, score 100/100.

The lab is a rule-based simulator, so these reports show what the output looks like, not the
detection quality against a real model. For that, see [`../VALIDATION.md`](../VALIDATION.md).
