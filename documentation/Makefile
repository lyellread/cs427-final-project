PANDOC_OPTS = --metadata-file metadata.yml -V geometry:margin=1in --highlight=tango
PANDOC_DOCKER = docker run --rm -v $(shell pwd):/data -u $(shell id -u):$(shell id -g) detjensrobert/arch-pandoc

all: docs

docs: $(wildcard *.md)
	pandoc $(sort $(wildcard *.md)) -o documentation.pdf $(PANDOC_OPTS)

docker: $(wildcard *.md)
	$(PANDOC_DOCKER) $(sort $(wildcard *.md)) -o documentation.pdf $(PANDOC_OPTS)

clean:
	rm -f $(wildcard *.pdf)
