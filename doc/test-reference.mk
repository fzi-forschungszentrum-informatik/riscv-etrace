# This Makefile runs the simple example in testing mode against reference flow
# tests.
#
# Usage:
#
#       make -f test-reference.mk SUITE=<test suite dir>
#
# Where `test suite dir` is the suite directory produced when running the
# reference flow's `run_regression.sh` script, e.g. `itype3_basic` in a
# directory `regression_20250624_124010`.
#
# This Makefile will produce the parameter files `params_32.toml` and
# `params_64.toml` in the current working directory and run the simple
# example for all test files for which a trace file is present.

SPIKE := $(SUITE)/../spike/
TEST_FILE_DIR := $(SUITE)/../../tests/test_files/
PK := $(TEST_FILE_DIR)pk.riscv

TRACES ?= $(basename $(notdir $(wildcard $(SUITE)/*.te_inst_raw)))
REFERENCE_TRACES := $(addprefix reference/,$(TRACES))

PROJ_DIR := $(dir $(real $(lastword $(MAKEFILE_LIST))))
EXAMPLES_DIR := $(PROJ_DIR)target/debug/examples/
DECODER := $(TARGETS_DIR)simple

CARGO ?= cargo
EGREP ?= egrep
FILEUTIL ?= file
MKDIR ?= mkdir -p

ELF_PARAMS = $(patsubst %-bit,params_%.toml,$(firstword \
	$(filter %-bit,$(shell $(FILEUTIL) -b $(1)))\
))

define DO_DECODER_RULE =
$(1): $(2) $(3) $(4) $(EXAMPLES_DIR)simple
	$(EXAMPLES_DIR)simple $(2) -p $(3) --spike-bootrom -r $(4) >> /dev/null
endef

DECODER_RULE = $(let base,$(basename $(notdir $(1))),$(let elf,\
	$(wildcard $(addprefix $(TEST_FILE_DIR)$(base),.riscv .pk)),\
	$(call DO_DECODER_RULE,$(1),\
		$(2)$(base).te_inst_raw \
		$(elf) $(if $(filter %.pk,$(elf)),$(TEST_FILE_DIR)pk.riscv),\
		$(call ELF_PARAMS,$(elf)),\
		$(SPIKE)$(base).spike_pc_trace\
	)\
))

all: reference_tests

clean:
	$(RM) $(PARAMS_FILES)

reference_tests: $(REFERENCE_TRACES)

$(foreach trace,$(REFERENCE_TRACES),$(eval $(call DECODER_RULE,$(trace),$(SUITE))))

PARAMS_FILES := params_32.toml params_64.toml

$(PARAMS_FILES): params_%.toml: $(SUITE)hardware_%.scf
	$(EGREP) -v '^[#[]' $^ > $@

$(EXAMPLES_DIR)%: .PHONY
	$(CARGO) build --all-features --example $(@F)

.PHONY:
