PANDOC_OPTS = --metadata-file metadata.yml -V geometry:margin=1in --highlight=tango

all: combined

combined: $(wildcard *.md)
	pandoc $(wildcard *.md) -o documentation.pdf $(PANDOC_OPTS)

clean:
	rm -f $(wildcard *.pdf)
