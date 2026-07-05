# ticketconnect — top-level build

COMPONENTS := ticket-agent

.PHONY: all clean help $(COMPONENTS)

all: $(COMPONENTS) ## Build all buildable components

$(COMPONENTS): ## Build a single component
	$(MAKE) -C $@

clean: ## Remove build artifacts
	@for c in $(COMPONENTS); do $(MAKE) -C $$c clean; done

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | sort \
		| awk 'BEGIN{FS=":.*## "}{printf "  %-14s %s\n", $$1, $$2}'
