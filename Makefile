CLANG ?= clang
CFLAGS += -D__TARGET_ARCH_x86 -D__x86_64__ -target bpf -g -c -O2
CFLAGS += -g -no-pie -fno-builtin -Wall

GCC ?= gcc
GCCFLAGS = -lm -lbpf

SCP = scp

OBJECT = filter.o
OUTPUT = $(OBJECT:.o=)

NEURO = neuro neuro_learn

UTILS = receiver configure dump


ETHDEV = xdp-local
#ETHDEV = eno1
# eth0 || eno1 || wlan0...


all: check_installed neuro $(OUTPUT) $(UTILS)

neuro:
	gcc perceptron.c -o perceptron.o -O2 -Wall -fPIC -c
	gcc perceptron.o -shared -o libperceptron.so
	gcc neuro.c -o neuro  		-D__LEARN__=0 -lm -ldl -lbpf
	gcc neuro.c -o neuro_learn	-D__LEARN__=1 -lm -ldl -lbpf

$(UTILS):
	$(GCC) $@.c -o $@ $(GCCFLAGS)


$(OUTPUT):
	$(CLANG) $@.c -o $@.o $(CFLAGS)

clean:
	rm $(NEURO) $(OBJECT) $(UTILS) *.o


install:
	sleep 1
	ip link set dev $(ETHDEV) xdp obj $(OBJECT) sec xdp
	bpftool map pin name ip_counter /sys/fs/bpf/ip_counter
	bpftool map pin name ringbuf_map /sys/fs/bpf/ringbuf_map
#	./configure


delete:
	ip link set dev $(ETHDEV) xdp off
	rm /sys/fs/bpf/ip_counter
	rm /sys/fs/bpf/ringbuf_map


MODELS_PATH	= models
RULES_PATH	= models/rules
DATA_PATH	= models/data

dataset:
	python3 $(RULES_PATH)/parse_rules.py $(RULES_PATH)/emerging-all.rules > $(DATA_PATH)/dataset_emerging

kill:
	@pidof $(NEURO) 2>/dev/null | xargs -r kill -9
	@pidof $(UTILS) 2>/dev/null | xargs -r kill -9

deploy:
	$(call CHECK_INSTALLED,$(SCP))
	#nonimplemented
#	$(LOGIN) scp $(OBJECT) $(UTILS) $(SCPDEST)
#	$(LOGIN) scp $(SCPDEST)/dumpstack ./


check_installed:
	$(call CHECK_INSTALLED,$(GCC))
	$(call CHECK_INSTALLED,$(CLANG))
	$(call CHECK_INSTALLED,bpftool)
	$(call CHECK_INSTALLED,ip)



# check installed

BOLD := \e[1m
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m  # No Color

CHECK_INSTALLED = \
	@command -v $1 >/dev/null 2>&1 && { printf "$(GREEN)$(BOLD)[$1] found$(NC)\n"; } || { printf "$(RED)$(BOLD)Error: $1 is not installed. Aborting.$(NC)\n"; exit 1; }