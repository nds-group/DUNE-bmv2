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
RESULTS_FILE := ./results.txt
COMBINED_PCAPS_FILE := ./pcaps/combined.csv
GROUND_TRUTH_FILE := /nas_storage/shared/ToN-IoT/ToN_IoT_Test_Flow_PktCounts.csv 



P4C := p4c-bm2-ss

P4_FLAGS := --std p4-16 -I $(INCLUDE_DIR)
P4_FLAGS_RUNTIME = --p4runtime-files $(OBJECTS_DIR)/$*.p4.p4info.txtpb
P4_FLAGS_DEPS = -MD -MP -MT $(OBJECTS_DIR)/$*.json -MF $(OBJECTS_DIR)/$*.d



MN := sudo PATH="$(PATH)" `which mn`

MN_DIR := ./mininet


join_with_comma = $(shell echo $1 | sed 's/ \+/,/g')


MN_CUSTOM_CLASSES := $(shell find $(MN_DIR) -type f -name '*.py')
MN_CUSTOM := --custom=$(call join_with_comma,$(MN_CUSTOM_CLASSES))


CUSTOM_TOPOLOGY := configs/topos/topo_ton.json
FATTREE_TOPOLOGY := configs/topos/fattreetopo.json
MODELS := configs/models/ton.json
MODELS_DIR := ./models
TOPO_ARGS := topo=$(TOPOLOGY) \
			 models=$(MODELS) \
			 models_dir=$(MODELS_DIR) \
			 objects_dir=$(OBJECTS_DIR) \
			 log_dir=$(LOG_DIR) \
			 pcap_dir=$(PCAP_DIR) \
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
MN_TEST := --test=tonpcap

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
ARCHIVE_EXPERIMENT := tar -cvzf experiment.tar.gz \
		                $(PCAP_DIR) \
				$(LOG_DIR) \
				Makefile \
				$(RESULTS_FILE)


.PHONY: all
all: build


.PHONY: run
run: build | $(RUN_DIRS)
	$(MN) $(MN_ARGS) 2>&1 | tee $(LOG_DIR)/mn.log 

.PHONY: results
results: 
	   $(PROCESS_PCAPS)
	   $(COMPUTE_SCORES) 2>&1 >> $(RESULTS_FILE)
	   $(ARCHIVE_EXPERIMENT)

.PHONY: run-test
run-test: override MN_ARGS += $(MN_TEST)
run-test: run
	results


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
	$(RMDIR) $(OBJECTS_DIR)
	$(RMDIR) $(RUN_DIRS)
	$(RM) $(FATTREE_TOPOLOGY)
	$(RM) $(RESULTS_FILE)


-include $(DEPS)
