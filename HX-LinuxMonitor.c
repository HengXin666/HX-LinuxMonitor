#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/module.h>
#include <linux/kernel.h>
 
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
    security_add_hooks(my_hooks, ARRAY_SIZE(my_hooks), &lsmId);
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