obj-m := rootkit.o
KERNELDIR := ../linux-5.4
PWD := $(shell pwd)
OUTPUT := $(obj-m) $(obj-m:.o=.ko) $(obj-m:.o=.mod.o) $(obj-m:.o=.mod.c)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
