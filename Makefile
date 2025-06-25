TARGET=HX-LinuxMonitor
OBJ=$(TARGET).o 
MODULE=$(TARGET).ko
obj-m+=$(OBJ)

EXTRA_CFLAGS+=-g -O2 # -x c++ # 左边这样写是编译c++
CURRENT_PATH:=$(shell pwd)
LINUX_KERNAL:=$(shell uname -r)
LINUX_KERNAL_PATH:=/lib/modules/$(LINUX_KERNAL)/build

all: hx

hx:
	make -j $(nrpoc) -C $(LINUX_KERNAL_PATH) M=$(CURRENT_PATH) modules

i:  install
	@dmesg | tail -n 5

install:
# 安装模块
	@sudo insmod $(CURRENT_PATH)/$(MODULE)

un: uninstall
	@dmesg | tail -n 5
 
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

d: 	debug
debug:
	@dmesg | tail -n 5

.PHONY:all install clean hx
