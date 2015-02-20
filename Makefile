SRC := mfs_imap_parse.c mfs_imap.c mfs_cmdqueue.c mfs_client.c		\
       mfs_imap_send.c mfs_file.c mfs_inode.c mfs_super.c mfs_mod.c
INC := mfs_imap_parse.h mfs_imap.h mfs_cmdqueue.h mfs_client.h		\
       mfs_imap_send.h mfs_file.h mfs_dir.h mfs_inode.h mfs_super.h
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
	cp $(SRC) Makefile $(INC) $(KBUILD)/
	$(MAKE) -C $(KERNDIR) M=$(PWD)/$(KBUILD) modules
	rm $(SRC:%=$(KBUILD)/%) $(KBUILD)/Makefile

build:
	mkdir -p build

clean:
	rm -f $(KOBJ:%=$(KBUILD)/%)

distclean:
	rm -rf $(KBUILD)

endif
