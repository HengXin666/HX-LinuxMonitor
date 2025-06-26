# HX-LinuxMonitor
use LSM monitor

- https://www.jianshu.com/p/9a640329449b
- https://liwugang.github.io/2020/10/18/introduce_lsm.html

- https://github.com/zhangying098/knowledge-hub/blob/b31f1a42e50b4fcaf4a7b83b64ecc8b8a15121ca/kernel_insight/LSM/README.md

> LSM不能作为内核模块动态加载?!
>
>  - https://just4coding.com/2023/12/01/lsm-hook/
>  - https://zhuanlan.zhihu.com/p/423247670
>
> 类似于我去hook那个存放lsm的表, 以实现动态加载.

- 可能的示例: https://github.com/oxmrtn/KernelTesting/blob/main/srcs/LSMHook.c

最可能的解决方案: https://www.jianshu.com/p/d732b0160493

```c
// https://just4coding.com/2023/12/01/lsm-hook/
#include <linux/lsm_hooks.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/stop_machine.h>

/*
make -j  -C /lib/modules/5.10.0-8-generic/build M=/home/kylin/hx/code/HX-LinuxMonitor modules
make[1]: 进入目录“/usr/src/linux-headers-5.10.0-8-generic”
  CC [M]  /home/kylin/hx/code/HX-LinuxMonitor/HX-LinuxMonitor.o
  MODPOST /home/kylin/hx/code/HX-LinuxMonitor/Module.symvers
ERROR: modpost: "security_hook_heads" [/home/kylin/hx/code/HX-LinuxMonitor/HX-LinuxMonitor.ko] undefined!
ERROR: modpost: "kallsyms_lookup_name" [/home/kylin/hx/code/HX-LinuxMonitor/HX-LinuxMonitor.ko] undefined!
make[2]: *** [scripts/Makefile.modpost:124：/home/kylin/hx/code/HX-LinuxMonitor/Module.symvers] 错误 1
make[2]: *** 正在删除文件“/home/kylin/hx/code/HX-LinuxMonitor/Module.symvers”
make[1]: *** [Makefile:1752：modules] 错误 2
*/
static int my_file_open(struct file *file)
{
    pr_info("file open: %s\n", file->f_path.dentry->d_iname);
    return 0;
}



static struct security_hook_heads *heads_symbol;
struct security_hook_list hooks[] = {
    LSM_HOOK_INIT(file_open, my_file_open),
};

static int hook_lsm(void *arg)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        hooks[i].lsmid->lsm = "lsmhook";
        hooks[i].head = (struct hlist_head *) ((unsigned long)hooks[i].head + (unsigned long)heads_symbol);
        hlist_add_tail_rcu(&hooks[i].list, hooks[i].head);
    }

    return 0;
}


static int unhook_lsm(void *arg)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        hlist_del_rcu(&hooks[i].list);
    }

    return 0;
}

static int lsm_info_get(void)
{
    heads_symbol = (struct security_hook_heads *) kallsyms_lookup_name("security_hook_heads");
    if (heads_symbol == NULL) {
        pr_err("symbol security_hook_heads not found\n");
        return -1;
    }

    pr_info("symbol security_hook_heads: 0x%lx\n", (unsigned long)heads_symbol);

    return 0;
}

static int __init lsmhook_init(void)
{
    pr_info("lsm hook module init\n");

    if (lsm_info_get() != 0) {
        pr_err("get LSM information failed\n");
        return -1;
    }

    pr_info("start hook LSM\n");
    stop_machine(hook_lsm, NULL, NULL);

    return 0;
}

static void __exit lsmhook_exit(void)
{
    stop_machine(unhook_lsm, NULL, NULL);
    pr_info("exit\n");
}

module_init(lsmhook_init);
module_exit(lsmhook_exit);

MODULE_LICENSE("GPL");
```

备用方案: [linux内核编程入门--系统调用监控文件访问](https://www.cnblogs.com/lqerio/p/12106855.html)

- 更合适的: [动手写一个基于Linux内核的网络数据包拦截扩展](https://rivers.chaitin.cn/blog/cqj64sh0lnedo7thptp0)

文件的 LSM 的暂时不行... 先把网络的搞出来

```C
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/lsm_hooks.h>
 
/*
make -j  -C /lib/modules/5.10.0-8-generic/build M=/home/kylin/hx/code/HX-LinuxMonitor modules
make[1]: 进入目录“/usr/src/linux-headers-5.10.0-8-generic”
  CC [M]  /home/kylin/hx/code/HX-LinuxMonitor/HX-LinuxMonitor.o
  MODPOST /home/kylin/hx/code/HX-LinuxMonitor/Module.symvers
ERROR: modpost: "security_hook_heads" [/home/kylin/hx/code/HX-LinuxMonitor/HX-LinuxMonitor.ko] undefined!
ERROR: modpost: "security_add_hooks" [/home/kylin/hx/code/HX-LinuxMonitor/HX-LinuxMonitor.ko] undefined!
make[2]: *** [scripts/Makefile.modpost:124：/home/kylin/hx/code/HX-LinuxMonitor/Module.symvers] 错误 1
*/

// 文件打开时的钩子函数
static int my_file_open(struct file* file)
{
    // 打印文件名
    if (file && file->f_path.dentry && file->f_path.dentry->d_name.name) {
        pr_info("File opened: %s\n", file->f_path.dentry->d_name.name);
    }
    return 0; // 返回 0 表示允许操作继续
}
 
// 权限检查时的钩子函数
static int my_inode_permission(struct inode *inode, int mask)
{
    // 打印 inode 编号和权限掩码
    if (inode) {
        pr_info("Permission check for inode: %lu, mask: %d\n", inode->i_ino, mask);
    }
    return 0; // 返回 0 表示允许访问
}
 
// 定义 LSM 钩子列表
static struct security_hook_list my_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(file_open, my_file_open),
    LSM_HOOK_INIT(inode_permission, my_inode_permission),
};
 
static struct lsm_id lsmId;

// 初始化 LSM 模块
static int __init lsm_init(void)
{
    pr_info("Initializing My LSM Module for File Operations\n");
    lsmId.lsm = "my_file_lsm";
    security_add_hooks(my_hooks, sizeof(my_hooks), &lsmId);
    return 0;
}
 
// 卸载 LSM 模块
static void __exit lsm_exit(void)
{
    pr_info("Exiting My LSM Module for File Operations\n");
}
 
module_init(lsm_init);
module_exit(lsm_exit);
 
MODULE_LICENSE("GPL");
// MODULE_AUTHOR("Heng_Xin");
// MODULE_DESCRIPTION("A custom LSM module to intercept file operations");
```

- https://blog.csdn.net/qq_42931917/article/details/108887284 [hook 系统读写]

- https://github.com/noahyzhang/file_io_hook 文件 IO 监控

- https://blog.csdn.net/jinking01/article/details/126728429 Linux利用hook技术实现文件监控和网络过滤

```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/namei.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("File Open Monitor");

// 定义 kprobe 结构体
static struct kprobe open_kp;

// 原始 do_sys_openat2 函数类型
typedef long (*openat2_func_t)(int, const char __user *, struct open_how *);

// kprobe 前置处理函数
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    int dfd = (int)regs->di;                          // 第一个参数：目录文件描述符
    const char __user *filename = (const char __user *)regs->si; // 第二个参数：文件名
    struct open_how *how = (struct open_how *)regs->dx; // 第三个参数：打开方式
    
    char fname[256] = {0};
    char process_name[TASK_COMM_LEN] = {0};
    
    // 获取进程名
    get_task_comm(process_name, current);
    
    // 安全地从用户空间复制文件名
    if (strncpy_from_user(fname, filename, sizeof(fname) - 1) > 0) {
        printk(KERN_INFO "FileOpenMonitor: Process %s (PID: %d) opening: %s\n",
               process_name, task_pid_nr(current), fname);
    }

    return 0; // 继续执行原函数
}

static int __init monitor_init(void)
{
    open_kp.pre_handler = handler_pre;
    
    // 根据内核版本设置要钩住的函数名
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    open_kp.symbol_name = "do_sys_openat2";  // Linux 5.6+
#else
    open_kp.symbol_name = "do_sys_open";     // Linux < 5.6
#endif

    // 注册 kprobe
    if (register_kprobe(&open_kp)) {
        printk(KERN_ERR "Failed to register kprobe\n");
        return -1;
    }

    printk(KERN_INFO "FileOpenMonitor installed\n");
    return 0;
}

static void __exit monitor_exit(void)
{
    unregister_kprobe(&open_kp);
    printk(KERN_INFO "FileOpenMonitor removed\n");
}

module_init(monitor_init);
module_exit(monitor_exit);
```
