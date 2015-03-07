SRC := mfs_imap_parse.c mfs_imap.c mfs_cmdqueue.c mfs_client.c		\
       mfs_imap_send.c mfs_file.c mfs_inode.c mfs_super.c mfs_mod.c
INC := mfs_imap_parse.h mfs_imap.h mfs_cmdqueue.h mfs_client.h		\
       mfs_imap_send.h mfs_file.h mfs_dir.h mfs_inode.h mfs_super.h
TOOLSDIR := tools
BUILDDIR := build
KBUILD := $(BUILDDIR)/fs
KOBJ := $(SRC:%.c=%.o)

ifeq ($(DEBUG), 1)
KFLAGS := -DDEBUG=1
endif

# We are called from the kernel (this makefile call the kernel's one which
# call's this one. So if KERNELRELEASE is defined we are at the second called to
# this makefile
ifneq ($(KERNELRELEASE),)
	obj-m := mfs.o
	mfs-y := $(KOBJ)
	ccflags-y := $(KFLAGS)

# Here we are at the first call
else
KERNDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default: $(SRC) $(INC) Makefile | buildtools builddir
	cp $(SRC) Makefile $(INC) $(KBUILD)/
	$(MAKE) -C $(KERNDIR) M=$(PWD)/$(KBUILD) modules
	rm $(SRC:%=$(KBUILD)/%) $(INC:%=$(KBUILD)/%) $(KBUILD)/Makefile

buildtools:
	$(MAKE) -C $(TOOLSDIR) BUILDDIR=$(PWD)/$(BUILDDIR)

cleantools:
	$(MAKE) -C $(TOOLSDIR) BUILDDIR=$(PWD)/$(BUILDDIR) clean

mrpropertools:
	$(MAKE) -C $(TOOLSDIR) BUILDDIR=$(PWD)/$(BUILDDIR) clean

builddir:
	mkdir -p $(KBUILD)

clean: cleantools
	rm -f $(KOBJ:%=$(KBUILD)/%)

distclean: mrpropertools
	rm -rf $(BUILDDIR)

endif
