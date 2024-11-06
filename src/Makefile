# Top-level Makefile in the src directory

SUBDIRS := lsm tracepoint raw_tracepoint

.PHONY: all clean

all:
	@for dir in $(SUBDIRS); do \
		echo "Building in $$dir..."; \
		$(MAKE) -C $$dir; \
	done

clean:
	@for dir in $(SUBDIRS); do \
		echo "Cleaning in $$dir..."; \
		$(MAKE) -C $$dir clean; \
	done
