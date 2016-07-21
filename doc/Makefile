SRC=thesis
CC=pdflatex
BIBTEX=bibtex
	
default: pdf clean
	
pdf: $(SRC).tex
	$(CC) $(SRC)
#	$(BIBTEX) $(SRC)
#	$(CC) $(SRC)
	$(CC) $(SRC)

clean:
	@for i in '*.aux' '*.log' '*.out' '*.bbl' '*.blg' '*.dvi' '*.toc' '*.lot' '*.lof' '*.backup' '*~' '*600pk' '*.514pk' '*.tfm'; do   \
	find . -name "$$i" -exec rm {} \;;                                                              \
	done

#cleanall: clean
#	rm -rf $(SRC).pdf