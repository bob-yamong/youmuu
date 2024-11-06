# Top-level Makefile in the src directory

SUBDIRS := lsm tracepoint raw_tracepoint

.PHONY: all clean

# ANSI color codes
GREEN := \033[0;32m
BLUE := \033[0;34m
YELLOW := \033[1;33m
RESET := \033[0m

all:
	@for dir in $(SUBDIRS); do \
		echo ""; \
		echo "$(YELLOW)====================================$(RESET)"; \
		echo "$(GREEN) Building in $$dir $(RESET)"; \
		echo "$(YELLOW)====================================$(RESET)"; \
		$(MAKE) -C $$dir; \
	done

clean:
	@for dir in $(SUBDIRS); do \
		echo ""; \
		echo "$(YELLOW)------------------------------------$(RESET)"; \
		echo "$(BLUE) Cleaning in $$dir $(RESET)"; \
		echo "$(YELLOW)------------------------------------$(RESET)"; \
		$(MAKE) -C $$dir clean; \
	done
