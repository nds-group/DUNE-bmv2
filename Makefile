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



P4C := p4c-bm2-ss

P4_FLAGS := --std p4-16 -I $(INCLUDE_DIR)
P4_FLAGS_RUNTIME = --p4runtime-files $(OBJECTS_DIR)/$*.p4.p4info.txtpb
P4_FLAGS_DEPS = -MD -MP -MT $(OBJECTS_DIR)/$*.json -MF $(OBJECTS_DIR)/$*.d



MN := sudo PATH="$(PATH)" `which mn`

MN_DIR := ./mininet


join_with_comma = $(shell echo $1 | sed 's/ \+/,/g')


MN_CUSTOM_CLASSES := $(shell find $(MN_DIR) -type f -name '*.py')
MN_CUSTOM := --custom=$(call join_with_comma,$(MN_CUSTOM_CLASSES))


TOPOLOGY := configs/topos/topo_ton.json
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
			 spines=2 \
			 leafs=2 \
			 hosts_per_leaf=1


MN_TOPO_CLASS := dunefattree
MN_TOPO := --topo=$(MN_TOPO_CLASS),$(call join_with_comma,$(TOPO_ARGS))
MN_SWITCH := --switch=p4simpleswitchgrpc
MN_CONTROLLER := --controller=p4controller,topo=$(TOPOLOGY),log_dir=$(LOG_DIR),log_level=${LOG_LEVEL}
MN_LINK := --link=p4link


MN_ARGS := $(MN_CUSTOM) $(MN_TOPO) $(MN_HOST) $(MN_SWITCH) $(MN_CONTROLLER) $(MN_LINK)



.PHONY: all
all: build


.PHONY: run
run: build | $(RUN_DIRS)
	$(MN) $(MN_ARGS) -v debug


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


-include $(DEPS)
