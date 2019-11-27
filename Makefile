obj-m	:= LSM.o
KERNELDIR ?= /usr/src/kernels/$(shell uname -r)/
KERNEL_VER=$(shell uname -r)

SCT   := $(shell sudo -S grep " sys_call_table" /boot/System.map-$(KERNEL_VER) | awk '{ print $$1; }')
SCT32 := $(shell sudo -S grep "ia32_sys_call_table" /boot/System.map-$(KERNEL_VER) | awk '{ print $$1; }')

EXTRA_CFLAGS += -Dsys_call_table_addr="((void**)0x$(SCT))"
EXTRA_CFLAGS += -Dia32_sys_call_table_addr="((void**)0x$(SCT32))" -D__enable_32bits_support
PWD       := $(shell pwd)

all: default

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
#	-sudo -S  rmmod -f LSM.ko
#	-sudo -S  modprobe -rf LSM.ko
#	sudo -S insmod LSM.ko


clean:
	rm -rf *.o *core .depend .*.cmd *.ko *.mod.c .tmp_versions
