# SPDX-License-Identifier: GPL-2.0
ifneq ($(KERNELRELEASE),)

obj-m := bcn_guard.o

else

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build

# A kernel built with clang (CachyOS ThinLTO, for example) needs its modules
# built with the LLVM toolchain as well.
ifneq ($(shell grep -s '^CONFIG_CC_IS_CLANG=y' $(KDIR)/.config),)
LLVM ?= 1
export LLVM
endif

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean

endif
