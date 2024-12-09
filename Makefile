# tool macros
CC := mpicc
CFLAGS := # FILL: compile flags

# path macros
BIN_PATH := bin
SRC_PATH := src

# compile macros
TARGET_IT := $(BIN_PATH)/it_golden
TARGET_PAR := $(BIN_PATH)/pr_golden

# clean files list
CLEAN_LIST := $(TARGET_IT) \
			  $(TARGET_PAR)

# default rule
default: makedir all

# non-phony targets
$(TARGET_IT): $(SRC_PATH)/mitm.c
	@echo Programme séquentiel:
	$(CC) $< $(CFLAGS) -o $@ $(CFLAGS)

$(TARGET_PAR): $(SRC_PATH)/mitm_paral.c
	@echo Programme parallèle:
	$(CC) $< $(CFLAGS) -o $@ $(CFLAGS)

# phony rules
.PHONY: makedir
makedir:
	@mkdir -p $(BIN_PATH)

.PHONY: all
all: seq par

.PHONY: seq
seq: $(TARGET_IT)

.PHONY: par
par: $(TARGET_PAR)

.PHONY: clean
clean:
	@echo CLEAN $(CLEAN_LIST)
	@rm -f $(CLEAN_LIST)

