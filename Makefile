
all: clean pqcrypto

pqcrypto:
	$(MAKE) --file=Makefile_pqcrypto

clean:
	$(MAKE) --file=Makefile_pqcrypto clean
	rm -rf build
	mkdir build

.PHONY: clean