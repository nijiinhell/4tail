# 4tail is developed as lib/*.sh sections loaded by the ./4tail.sh entrypoint.
# `make build` concatenates them, in load order, into a single-file dist/4tail.sh
# that is identical to the classic standalone script (copy that one file anywhere).

LIBS = lib/00-prelude.sh lib/config.sh lib/cli.sh lib/dashboard.sh lib/helpers.sh \
       lib/agent_tools.sh lib/blueprints.sh lib/ai.sh lib/doctor.sh \
       lib/p_recon.sh lib/p_js.sh lib/p_plan.sh lib/p_fuzz.sh lib/p_funnel.sh \
       lib/p_nuclei.sh lib/p_agent.sh lib/p_report.sh

.PHONY: build check clean

build:
	@mkdir -p dist
	@cat $(LIBS) > dist/4tail.sh
	@chmod +x dist/4tail.sh
	@echo "built dist/4tail.sh ($$(wc -l < dist/4tail.sh) lines)"

# Syntax-check the entrypoint and the concatenated sections.
check:
	@bash -n 4tail.sh && echo "entrypoint: OK"
	@tmp=$$(mktemp); cat $(LIBS) > "$$tmp"; bash -n "$$tmp" && echo "sections: OK"; rm -f "$$tmp"

clean:
	@rm -rf dist
