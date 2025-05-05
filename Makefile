BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs
DIRS = $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

P4C = p4c-bm2-ss
SOURCES_DIR = p4
SOURCES = $(shell find $(SOURCES_DIR) -type f -name "*.p4")
TARGETS := $(SOURCES:$(SOURCES_DIR)/%.p4=$(BUILD_DIR)/%.json)

all: run

run: build
	sudo PATH="$(PATH)" python3 run.py

stop:
	sudo PATH="$(PATH)" `which mn` -c

build: dirs $(TARGETS)

$(BUILD_DIR)/%.json: $(SOURCES_DIR)/%.p4
	$(P4C) \
		--p4v 16 \
		--p4runtime-files $(basename $@).p4.p4info.txtpb \
		-o $@ \
		$<

dirs:
	mkdir -p $(DIRS)

clean: stop
	rm -rf $(DIRS)

.PHONY: all run debug run_switch build dirs stop clean
