.PHONY: install uninstall test benchmark list key-check key-clear build build-j3h145 build-j3r180 all

GP_HELPER  = python3 gp_helper.py
APPLET     ?= memorycard
CAP_DIR    = build/cap
TEST_DIR   = tests/tests
LOG_DIR    = artifacts/logs
TS         = $(shell date -u +%Y%m%dT%H%M%SZ)

APPLETS = teapot memorycard singleusekey blindoracle

CAP_FILES := $(foreach a,$(APPLETS),$(CAP_DIR)/$(shell echo $(a) | sed 's/.*/\u&/')Applet.cap)

PACKAGE_AID_teapot       = B00B5111CA
PACKAGE_AID_memorycard   = B00B5111CB
PACKAGE_AID_singleusekey = B00B5111CD
PACKAGE_AID_blindoracle  = B00B5111CE
PACKAGE_AID              = $(PACKAGE_AID_$(APPLET))

TEST_FILE_memorycard   = test_specter_diy.py
TEST_FILE_singleusekey = test_singleusekey.py
TEST_FILE_blindoracle  = test_blindoracle.py
TEST_FILE_teapot       = test_specter_diy.py
TEST_FILE              = $(TEST_FILE_$(APPLET))

CAP_FILE_memorycard   = MemoryCardApplet.cap
CAP_FILE_singleusekey = SingleUseKeyApplet.cap
CAP_FILE_blindoracle  = BlindOracleApplet.cap
CAP_FILE_teapot       = TeapotApplet.cap
CAP_FILE              = $(CAP_FILE_$(APPLET))

all: build

build:
	ant all

build-j3h145:
	ant all -DJCKIT=sdks/jc304_kit

build-j3r180:
	ant all -DJCKIT=sdks/jc305u3_kit

build/%:
	ant $(@F)

install:
	@echo "==> Installing $(APPLET) ($(CAP_FILE))"
	@test -f $(CAP_DIR)/$(CAP_FILE) || (echo "Error: $(CAP_DIR)/$(CAP_FILE) not found. Run 'make build' first." && exit 1)
	@$(GP_HELPER) --install $(CAP_DIR)/$(CAP_FILE)

uninstall:
	@echo ""
	@echo "  ╔══════════════════════════════════════════════════════════╗"
	@echo "  ║  WARNING: This will DELETE the applet from the card.    ║"
	@echo "  ║  All stored secrets, keys, and PINs will be LOST.        ║"
	@echo "  ║  This cannot be undone.                                  ║"
	@echo "  ╚══════════════════════════════════════════════════════════╝"
	@echo ""
	@echo -n "  Type 'yes' to confirm: "; read confirm && [ "$$confirm" = "yes" ]
	@echo "==> Uninstalling $(APPLET) (package AID: $(PACKAGE_AID))"
	@$(GP_HELPER) --delete $(PACKAGE_AID)

test:
	@echo "==> Running tests for $(APPLET)"
	@test -f $(CAP_DIR)/$(CAP_FILE) || (echo "Error: $(CAP_DIR)/$(CAP_FILE) not found. Run 'make build' first." && exit 1)
	@echo "==> Checking if $(APPLET) is already installed..."
	@if $(GP_HELPER) --check-installed $(PACKAGE_AID) 2>/dev/null; then \
		echo "Error: $(APPLET) is already installed on the card."; \
		echo "Tests require a clean install. Run 'make uninstall APPLET=$(APPLET)' first."; \
		exit 1; \
	fi
	@echo "==> Installing $(APPLET)..."
	@$(GP_HELPER) --install $(CAP_DIR)/$(CAP_FILE)
	@mkdir -p $(LOG_DIR)
	@echo "==> Running pytest..."
	@cd $(TEST_DIR) && TEST_MODE=card python3 -m pytest $(TEST_FILE) -v \
		--tb=short 2>&1 | tee ../../$(LOG_DIR)/$(TS)-$(APPLET).log; \
		EXIT_CODE=$${PIPESTATUS[0]}; \
		echo "==> Uninstalling $(APPLET) (cleanup)..."; \
		$(GP_HELPER) --delete $(PACKAGE_AID) 2>/dev/null || true; \
		exit $$EXIT_CODE

benchmark:
	@mkdir -p artifacts/benchmarks
	@cd $(TEST_DIR) && TEST_MODE=card python3 benchmark_runner.py --gp-jar ../../gp.jar

list:
	@$(GP_HELPER) --list

key-check:
	@$(GP_HELPER) --key-check

key-clear:
	@$(GP_HELPER) --key-clear
