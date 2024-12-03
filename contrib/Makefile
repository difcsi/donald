.PHONY: default build

default: build config.mk

build: build-librunt


.PHONY: buid-librunt
build-librunt:
	$(MAKE) -C $(srcroot)/contrib/librunt

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(THIS_MAKEFILE)))/..

CONFIG_MK += -I $(realpath $(dir $(THIS_MAKEFILE)))/librunt/include

# write COFIG_MK to file
config.mk: $(subconfigs)
	@echo "CFLAGS += $(CONFIG_MK)" > $@

clean:
	rm -f config.mk