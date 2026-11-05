PAPER := garbled-stark-verifier
TEX := $(PAPER).tex
BIB := refs.bib
PDF := $(PAPER).pdf

LATEX ?= pdflatex
BIBTEX ?= bibtex
LATEX_FLAGS ?= -interaction=nonstopmode -halt-on-error -file-line-error

.DEFAULT_GOAL := all

.PHONY: all pdf check chk verify-data view clean distclean help

all: $(PDF)

pdf: $(PDF)

$(PDF): $(TEX) $(BIB)
	$(LATEX) $(LATEX_FLAGS) $(TEX)
	$(BIBTEX) $(PAPER)
	$(LATEX) $(LATEX_FLAGS) $(TEX)
	$(LATEX) $(LATEX_FLAGS) $(TEX)

check chk:
	@if command -v chktex >/dev/null 2>&1; then \
		chktex -q $(TEX); \
	else \
		echo "chktex not installed; skipping LaTeX lint"; \
	fi

verify-data:
	cd data && sha256sum -c SHA256SUMS

view: $(PDF)
	@xdg-open $(PDF) >/dev/null 2>&1 || \
		open $(PDF) >/dev/null 2>&1 || \
		echo "No PDF viewer configured."

clean:
	rm -f $(PAPER).aux $(PAPER).bbl $(PAPER).blg $(PAPER).log
	rm -f $(PAPER).out $(PAPER).toc $(PAPER).lof $(PAPER).lot
	rm -f $(PAPER).fls $(PAPER).fdb_latexmk $(PAPER).synctex.gz

distclean: clean
	rm -f $(PDF)

help:
	@echo "Targets:"
	@echo "  all, pdf    Build $(PDF) (default)"
	@echo "  check, chk  Run chktex when installed"
	@echo "  verify-data Verify archived measurement checksums"
	@echo "  view        Build and open the PDF"
	@echo "  clean       Remove LaTeX intermediate files"
	@echo "  distclean   Remove intermediates and $(PDF)"
