# Paper: Garbling a Hash-Based STARK Verifier for Bitcoin

A draft, not yet released. Every measurement is in the paper itself.

| file | what |
| --- | --- |
| `garbled-stark-verifier.tex` | the paper (built: `garbled-stark-verifier.pdf`) |
| `refs.bib` | its bibliography |
| `notes.md` | per-paper notes, the measurement record and the open points before release (§8) |
| `assert-disprove-reduction-survey.md` | the evidence-tiered study of ways to shrink Assert and Disprove |
| `data/` | local only, git-ignored: raw logs, dump tools, per-step patches and checksums |
| `refs/` | local only, git-ignored: PDFs of the papers read |

Build:

```
make            # or: pdflatex, bibtex, then pdflatex twice
```

The logs in `data/` are kept off the repository. Its `README.md` maps each log
to the test that regenerates it, and `make verify-data` checks the checksums.
The cumulative Plonky3 and Ziren changes behind the narrow-recursion figures
are in [`../patches/`](../patches/README.md).

Still to do before release: the author list, and the open points in
`notes.md` §8.
