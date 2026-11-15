# Paper: Toward Efficient Post-Quantum Bitcoin Bridges

The working draft of [IACR ePrint 2026/2877](https://eprint.iacr.org/2026/2877).
Every measurement is in the paper itself.

| file | what |
| --- | --- |
| `garbled-stark-verifier.tex` | the paper (built: `garbled-stark-verifier.pdf`) |
| `refs.bib` | its bibliography |
| `assert-disprove-reduction-survey.md` | the evidence-tiered study of ways to shrink Assert and Disprove |
| `data/` | local only, git-ignored: raw logs, dump tools, per-step patches and checksums |
| `refs/` | local only, git-ignored: PDFs of the papers read |
| `notes.md` | local only, git-ignored: working notes and the measurement record |

Build:

```
make            # or: pdflatex, bibtex, then pdflatex twice
```

The logs in `data/` are kept off the repository. Its `README.md` maps each log
to the test that regenerates it, and `make verify-data` checks the checksums.
The Plonky3 and Ziren commits behind the narrow-recursion figures, and the
commands that rebuild their tapes, are in [`../patches/`](../patches/README.md).
