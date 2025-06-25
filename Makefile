TARGET=HX-LinuxMonitor
OBJ=$(TARGET).o 
MODULE=$(TARGET).ko
obj-m+=$(OBJ)

EXTRA_CFLAGS+=-g++ -O2
CURRENT_PATH:=$(shell pwd)
LINUX_KERNAL:=$(shell uname -r)
LINUX_KERNAL_PATH:=/lib/modules/$(LINUX_KERNAL)/build

all: hx

hx:
	make -j $(nrpoc) -C $(LINUX_KERNAL_PATH) M=$(CURRENT_PATH) modules

i:  install
	dmesg

install:
# 安装模块
	@sudo insmod $(CURRENT_PATH)/$(MODULE)

un: uninstall
	dmesg

uninstall:
# 卸载模块
	@sudo rmmod $(CURRENT_PATH)/$(MODULE)
# @modprobe -r $(TARGET)
# @install $(MODULE) /lib/modules/$(shell uname -r)/kernel/drivers/hid
# @depmod
# @modprobe $(TARGET)

rm: clean
clean:
	make -C $(LINUX_KERNAL_PATH) M=$(CURRENT_PATH) clean

debug:
	dmesg

.PHONY:all install clean hx