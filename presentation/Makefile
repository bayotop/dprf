SRC=dp-prezentacia
CC=pdflatex

default: pdf

pdf: $(SRC).tex
	$(CC) $(SRC)
	$(CC) $(SRC)

#
# check embedded fonts in output pdf file
#
	@for FONT in `pdffonts $(SRC).pdf | grep Type | cut -b51-53`; do	\
		if [ $$FONT = "no" ]; then	 				\
			echo "Non embedded font found in output PDF file!";	\
		fi								\
	done

ps: $(SRC).tex
	$(CCC) $(SRC)
	$(CCC) $(SRC)
	$(CCC) $(SRC)
	dvips -f -t A4 $(SRC).dvi > $(SRC).ps

clean:
	rm -f *.aux *.log *.out *.bbl *.blg *.dvi *.ps *.toc *.lot *.lof *.backup *.vrb *.snm *.nav
	find . -name "*~" -exec rm {} \;
