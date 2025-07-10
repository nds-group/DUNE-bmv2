MKDIR := mkdir -p
RM    := rm -f
RMDIR := rm -fr



SOURCES_DIR := ./p4sources
INCLUDE_DIR := ./p4include
OBJECTS_DIR := ./p4objects

PCAP_DIR := ./pcaps
LOG_DIR := ./logs
RUN_DIRS := $(PCAP_DIR) $(LOG_DIR)



SOURCES := $(wildcard $(SOURCES_DIR)/*.p4)
OBJECTS := $(SOURCES:$(SOURCES_DIR)/%.p4=$(OBJECTS_DIR)/%.json)
DEPS := $(SOURCES:$(SOURCES_DIR)/%.p4=$(OBJECTS_DIR)/%.d)



P4C := p4c-bm2-ss

P4_FLAGS := --std p4-16 -I $(INCLUDE_DIR) 
P4_FLAGS_RUNTIME = --p4runtime-files $(OBJECTS_DIR)/$*.p4.p4info.txtpb 
P4_FLAGS_DEPS = -MD -MP -MT $(OBJECTS_DIR)/$*.json -MF $(OBJECTS_DIR)/$*.d



.PHONY: all
all: build


.PHONY: run
run: build | $(RUN_DIRS)
	# TODO : pass log and pcap dirs as param dune.py
	sudo PATH="$(PATH)" python3 dune.py


.PHONY: stop
stop:
	sudo PATH="$(PATH)" `which mn` -c


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
