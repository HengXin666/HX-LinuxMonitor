// https://rivers.chaitin.cn/blog/cqj64sh0lnedo7thptp0
// 开发时候需要安装本机内核版本 开发包
// sudo apt install linux-headers-$(uname -r)

/*
以及其他编译内核使用到的工具

sudo apt install build-essential
sudo add-apt-repository ppa:ubuntu-toolchain-r/test

make 编译后, 加载内核模块

sudo insmod main.ko

然后 lsmod 查看已经加载的模块

kylin@tq:~/hx/wk2$ lsmod
Module                  Size  Used by
main                   16384  0
cpuid                  16384  0

查看内核日志:
kylin@tq:~/hx/wk2$ dmesg
[30032.459789] First kernel module: Hello World!

卸载模块:
sudo rmmod main

再次查看内核日志:
[30251.733364] First kernel module has been removed
*/
// #include <linux/lsm_hook_defs.h>
#include <linux/init.h>
#include <linux/module.h>  
  
static int __init construct(void) {  
    pr_info("First kernel module: Hello World!\n");  
    return 0;  
}  
  
static void __exit destruct(void) {  
    pr_info("First kernel module has been removed\n");  
}  
  
module_init(construct);  
module_exit(destruct);  
  
MODULE_LICENSE("GPL");