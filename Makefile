# tool macros
CC := mpicc
CFLAGS := # FILL: compile flags

# path macros
BIN_PATH := bin
SRC_PATH := src

# compile macros
TARGET_IT := $(BIN_PATH)/it_golden
TARGET_PAR := $(BIN_PATH)/pr_golden
TARGET_PAR2 := $(BIN_PATH)/pr_golden2
TARGET_PAR3 := $(BIN_PATH)/pr_golden3

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

$(TARGET_PAR2): $(SRC_PATH)/mitm_paral2.c
	@echo Programme parallèle 2:
	$(CC) $< $(CFLAGS) -o $@ $(CFLAGS)

$(TARGET_PAR3): $(SRC_PATH)/mitm_paral3.c
	@echo Programme parallèle 3:
	$(CC) $< $(CFLAGS) -o $@ $(CFLAGS)

# phony rules
.PHONY: makedir
makedir:
	@mkdir -p $(BIN_PATH)

.PHONY: all
all: seq par par2 par3

.PHONY: seq
seq: $(TARGET_IT)

.PHONY: par
par: $(TARGET_PAR)

.PHONY: par2
par2: $(TARGET_PAR2)

.PHONY: par3
par3: $(TARGET_PAR3)

.PHONY: clean
clean:
	@echo CLEAN $(CLEAN_LIST)
	@rm -f $(CLEAN_LIST)

