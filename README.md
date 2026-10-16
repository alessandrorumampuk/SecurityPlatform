# SecurityPlatform

Security tooling collection. Currently contains:

## tools/vvm — Visual Vulnerability Mapping

Implements the VVM + AVM teaching method (see `VVM_AVM_AI_White_Paper.pdf`):
annotates a webpage screenshot, marking UI elements as potential vulnerability
entry points, and produces an AVM table (assumption → inversion → result).

```bash
python3 tools/vvm/vvm.py https://example.com/
python3 tools/vvm/vvm.py https://example.com/ -o out.png --check-links
```

Output: `vvm-*.png` (annotated screenshot) + `*-avm.md` (AVM table).
Rule-based only, one page load per run. Use only on sites you own or are
authorized to test.

Dependencies: `playwright`, `Pillow`.
