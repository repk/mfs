SRC := vmfs.c
KBUILD := build
KOBJ := $(SRC:%.c=%.o)

# We are called from the kernel (this makefile call the kernel's one which
# call's this one. So if KERNELRELEASE is defined we are at the second called to
# this makefile
ifneq ($(KERNELRELEASE),)
        obj-m := mfs.o
	mfs-y := $(KOBJ)

# Here we are at the first call
else
KERNDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default: build $(SRC) Makefile
	cp $(SRC) Makefile $(KBUILD)/
	$(MAKE) -C $(KERNDIR) M=$(PWD)/$(KBUILD) modules
	rm $(SRC:%=$(KBUILD)/%) $(KBUILD)/Makefile

build:
	mkdir -p build

endif
