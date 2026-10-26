# 4tail is developed as lib/*.sh sections loaded by the ./4tail.sh entrypoint.
# `make build` concatenates them, in load order, into a single-file dist/4tail.sh
# that is identical to the classic standalone script (copy that one file anywhere).

LIBS = lib/00-prelude.sh lib/config.sh lib/cli.sh lib/dashboard.sh lib/helpers.sh \
       lib/agent_tools.sh lib/blueprints.sh lib/ai.sh lib/doctor.sh \
       lib/p_recon.sh lib/p_plan.sh lib/p_fuzz.sh lib/p_js.sh lib/p_funnel.sh \
       lib/p_nuclei.sh lib/p_agent.sh lib/p_report.sh

.PHONY: build check lint test clean

build:
	@mkdir -p dist
	@cat $(LIBS) > dist/4tail.sh
	@chmod +x dist/4tail.sh
	@echo "built dist/4tail.sh ($$(wc -l < dist/4tail.sh) lines)"

# Syntax-check the entrypoint and the concatenated sections.
check:
	@bash -n 4tail.sh && echo "entrypoint: OK"
	@tmp=$$(mktemp); cat $(LIBS) > "$$tmp"; bash -n "$$tmp" && echo "sections: OK"; rm -f "$$tmp"

# ShellCheck the entrypoint + every section (skips cleanly if shellcheck isn't installed).
lint:
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck not installed - skipping"; exit 0; }
	@shellcheck -S warning -e SC2086,SC1090,SC1091,SC2016,SC2317,SC2034 4tail.sh $(LIBS) && echo "shellcheck: clean"

# Offline smoke test (serves a fixture, stubs httpx/nuclei/ffuf, asserts the data flow).
test:
	@bash tests/smoke.sh

clean:
	@rm -rf dist
