# If KERNELRELEASE is defined, we've been invoked from the kernel build system;
# we can use its language.
ifneq ($(KERNELRELEASE),)
	obj-m := multimode.o

# Otherwise we were called directly from the command line;
# invoke the kernel build system.
else

	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

	MOD_KER_OBJ = multimode.ko

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

insert:
	$(shell which insmod) $(MOD_KER_OBJ)

remove:
	$(shell which rmmod) $(MOD_KER_OBJ)

.PHONY: all clean install remove

endif
