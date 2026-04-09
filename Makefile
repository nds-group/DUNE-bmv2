MKDIR := mkdir -p
RM    := rm -f
RMDIR := rm -fr


SOURCES_DIR := ./p4sources
INCLUDE_DIR := ./p4include
OBJECTS_DIR := ./p4objects

PCAP_DIR := ./pcaps
LOG_DIR := ./logs
LOG_LEVEL := INFO
RUN_DIRS := $(PCAP_DIR) $(LOG_DIR)



SOURCES := $(wildcard $(SOURCES_DIR)/*.p4)
OBJECTS := $(SOURCES:$(SOURCES_DIR)/%.p4=$(OBJECTS_DIR)/%.json)
DEPS := $(SOURCES:$(SOURCES_DIR)/%.p4=$(OBJECTS_DIR)/%.d)
COMBINED_PCAPS_FILE := ./pcaps/combined.csv
GROUND_TRUTH_FILE ?= ./data/ToN_IoT_Test_Flow_PktCounts.csv



P4C := p4c-bm2-ss

P4_FLAGS := --std p4-16 -I $(INCLUDE_DIR)
P4_FLAGS_RUNTIME = --p4runtime-files $(OBJECTS_DIR)/$*.p4.p4info.txtpb
P4_FLAGS_DEPS = -MD -MP -MT $(OBJECTS_DIR)/$*.json -MF $(OBJECTS_DIR)/$*.d



MN := sudo PATH="$(PATH)" `which mn`

MN_DIR := ./dune


join_with_comma = $(shell echo $1 | sed 's/ \+/,/g')


MN_CUSTOM_CLASSES := $(shell find $(MN_DIR) -type f -name '*.py')
MN_CUSTOM := --custom=$(call join_with_comma,$(MN_CUSTOM_CLASSES))


CUSTOM_TOPOLOGY := configs/topos/topo_ton.json
FATTREE_TOPOLOGY := configs/topos/fattreetopo.json
MODELS := configs/models/ton.json
MODELS_DIR := ./models
PCAP_REGEX ?= ^pe_l[0-9]+$
SUPER_SPINES ?= 4
SPINES ?= 4
LEAFS ?= 6
PODS ?= 4
HOSTS_PER_LEAF ?= 2
TEST_PPS ?= 100
TEST_PCAP ?= ./data/ToN_IoT_test.pcap
TEST_PCAP_DIR ?= ./utils/experiment_pcaps
PKT_NUM ?=
RESULTS_FILE = results_p$(PODS)_ss$(SUPER_SPINES)_s$(SPINES)_l$(LEAFS)_h$(HOSTS_PER_LEAF)_$(TEST_PPS)pps.txt
SAVE_RESULTS ?= YES

TOPO_ARGS = models=$(MODELS) \
			 models_dir=$(MODELS_DIR) \
			 objects_dir=$(OBJECTS_DIR) \
			 log_dir=$(LOG_DIR) \
			 pcap_regex=$(PCAP_REGEX) \
			 pcap_dir=$(PCAP_DIR) \
			 test_pps=$(TEST_PPS) \
			 pkt_num=$(PKT_NUM) \
			 super_spines=$(SUPER_SPINES) \
			 pods=$(PODS) \
			 spines=$(SPINES) \
			 leafs=$(LEAFS) \
			 hosts_per_leaf=$(HOSTS_PER_LEAF)

TOPO_ARGS_LINEAR = models=$(MODELS) \
			 models_dir=$(MODELS_DIR) \
			 objects_dir=$(OBJECTS_DIR) \
			 log_dir=$(LOG_DIR) \
			 pcap_dir=$(PCAP_DIR) \
			 test_pcap=$(TEST_PCAP) \
			 test_pcap_dir=$(TEST_PCAP_DIR) \
			 test_pps=$(TEST_PPS) \
			 pkt_num=$(PKT_NUM) \
			 super_spines=1 \
			 pods=1 \
			 spines=1 \
			 leafs=1 \
			 hosts_per_leaf=1

MN_TOPO_CLASS := dunefattree
MN_TOPO := --topo=$(MN_TOPO_CLASS),$(call join_with_comma,$(TOPO_ARGS))
MN_SWITCH := --switch=p4simpleswitchgrpc,log_level=$(LOG_LEVEL)
MN_CONTROLLER := --controller=p4controller,topo_class=$(MN_TOPO_CLASS),topo=$(CUSTOM_TOPOLOGY),log_dir=$(LOG_DIR),log_level=$(LOG_LEVEL)
MN_LINK := --link=p4link
MN_TEST := 

MN_LOG_LEVEL := -v $(shell echo $(LOG_LEVEL) | tr '[:upper:]' '[:lower:]')


MN_ARGS := $(MN_CUSTOM) \
		   $(MN_TOPO) \
		   $(MN_HOST) \
		   $(MN_SWITCH) \
		   $(MN_CONTROLLER) \
		   $(MN_LINK) \
		   $(MN_LOG_LEVEL)


PROCESS_PCAPS := ./utils/process_result_pcaps.sh
COMPUTE_SCORES := python3 ./utils/calculate_score.py --results $(COMBINED_PCAPS_FILE) --ground-truth $(GROUND_TRUTH_FILE)

# Compute the next available tarball
BASENAME := experiment
NEXT_ARCHIVE_FILE := $(shell \
    i=1; \
    while [ -e "$(CURDIR)/$(BASENAME)_$$i.tar.gz" ]; do \
        i=$$((i+1)); \
    done; \
    echo "$(CURDIR)/$(BASENAME)_$$i.tar.gz" \
)
ARCHIVE_EXPERIMENT := tar -cvzf $(NEXT_ARCHIVE_FILE) \
		                $(PCAP_DIR) \
				$(LOG_DIR) \
				Makefile \
				$(RESULTS_FILE)

DB_SAVE :=  python utils/insert_to_db.py \
	    --file $(RESULTS_FILE) \
	    --archive $(NEXT_ARCHIVE_FILE)


.PHONY: all
all: build


EXPECTED_PCAPS := $(shell awk -F'=' '/^number_of_hosts/ {gsub(/[ \t]+/, "", $$2); print $$2}' utils/params.ini)
ACTUAL_PCAPS := $(words $(wildcard $(TEST_PCAP_DIR)/TON-IOT_*.pcap))

ifneq ($(EXPECTED_PCAPS),$(ACTUAL_PCAPS))
FORCE_PREPARE = FORCE
endif

$(TEST_PCAP_DIR)/.pcaps_prepared: ./utils/prepare_pcap_traces.py utils/params.ini $(TEST_PCAP) $(GROUND_TRUTH_FILE) $(FORCE_PREPARE)
	@if [ "$(EXPECTED_PCAPS)" -eq "$(ACTUAL_PCAPS)" ] && [ -n "$$(ls $(TEST_PCAP_DIR)/TON-IOT_*.pcap 2>/dev/null)" ] && [ ! utils/params.ini -nt $$(ls -t $(TEST_PCAP_DIR)/TON-IOT_*.pcap | head -1) ]; then \
		echo "Pcaps are already generated and up to date. Skipping generation."; \
	else \
		echo "Generating $(EXPECTED_PCAPS) pcap traces..."; \
		python3 ./utils/prepare_pcap_traces.py; \
	fi
	@ACTUAL=$$(ls -1 $(TEST_PCAP_DIR)/TON-IOT_*.pcap 2>/dev/null | wc -l); \
	if [ "$$ACTUAL" -ne "$(EXPECTED_PCAPS)" ]; then \
		echo "Error: Expected $(EXPECTED_PCAPS) pcap files, but found $$ACTUAL in $(TEST_PCAP_DIR)."; \
		exit 1; \
	fi
	@touch $@

FORCE:

$(TEST_PCAP) $(GROUND_TRUTH_FILE):
	@echo "Error: Required file $@ not found. Please provide it or update the configuration."
	@exit 1

.PHONY: run
run: build $(TEST_PCAP) $(GROUND_TRUTH_FILE) | $(RUN_DIRS)
	bash -o pipefail -c '$(MN) $(MN_ARGS) 2>&1 | tee "$(LOG_DIR)/mn.log"; ec=$$?; if grep -qE "Traceback|Caught exception" "$(LOG_DIR)/mn.log"; then exit 1; else exit $$ec; fi'

.PHONY: results
results: 
	   $(PROCESS_PCAPS)
	   $(COMPUTE_SCORES) > $(RESULTS_FILE) 2>&1
	   $(ARCHIVE_EXPERIMENT)
ifeq ($(SAVE_RESULTS),YES)
	   $(DB_SAVE)
	   @echo Saving results to DB
else
	   @echo Skipping saving results to DB
endif

.PHONY: run-test
run-test: override MN_ARGS += --test=tonfattree
run-test: $(TEST_PCAP_DIR)/.pcaps_prepared run
	$(MAKE) results

.PHONY: run-smoke-test
run-smoke-test: override PKT_NUM := 1000
run-smoke-test: override MN_ARGS := $(MN_CUSTOM) --topo=$(MN_TOPO_CLASS),$(call join_with_comma,$(TOPO_ARGS_LINEAR)) $(MN_HOST) $(MN_SWITCH) $(MN_CONTROLLER) $(MN_LINK) $(MN_LOG_LEVEL) --test=tonlinear
run-smoke-test: run

.PHONY: run-linear-test
run-linear-test: override MN_ARGS := $(MN_CUSTOM) --topo=$(MN_TOPO_CLASS),$(call join_with_comma,$(TOPO_ARGS_LINEAR)) $(MN_HOST) $(MN_SWITCH) $(MN_CONTROLLER) $(MN_LINK) $(MN_LOG_LEVEL) --test=tonlinear
run-linear-test: run
	$(MAKE) results

.PHONY: run-table-5
run-table-5:
	$(MAKE) run-test PODS=3 SPINES=4 LEAFS=4 SUPER_SPINES=1 HOSTS_PER_LEAF=2 TEST_PPS=100

.PHONY: stop
stop:
	$(MN) -c

.PHONY: build
build: $(OBJECTS)


$(OBJECTS_DIR)/%.json: $(SOURCES_DIR)/%.p4 | $(OBJECTS_DIR)
	$(P4C) $(P4_FLAGS) $(P4_FLAGS_RUNTIME) $(P4_FLAGS_DEPS) -o $@ $<


$(OBJECTS_DIR):
	$(MKDIR) $(OBJECTS_DIR)


$(RUN_DIRS):
	$(MKDIR) $(RUN_DIRS)


.PHONY: clean
clean: stop
	$(RMDIR) $(RUN_DIRS)
	$(RM) $(FATTREE_TOPOLOGY)

.PHONY: clean-all
clean-all: clean
	$(RMDIR) $(OBJECTS_DIR)
	$(RM) $(RESULTS_FILE)


-include $(DEPS)
