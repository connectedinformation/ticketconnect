# ticketconnect — top-level build (skeleton)

.PHONY: all clean help

all: ## Build all components (TBD)
	@echo "TODO: build ticket-agent, injector, bpf"

clean: ## Remove build artifacts
	@echo "TODO: clean"

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | sort \
		| awk 'BEGIN{FS=":.*## "}{printf "  %-10s %s\n", $$1, $$2}'
