#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include "../hx/hx_dir_tools.h"
#include "../hx/hx_path_tools.h"
#include "../hx/hx_log.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Heng_Xin");
MODULE_DESCRIPTION("Kprobe example to intercept .c file open");

// 数据
struct hx_str_node {
    const char* data;
    size_t n;
    struct hx_str_node* next;
};

static struct hx_str_node hx_file_list;
static struct hx_str_node hx_process_list;

// 头插法
void hx_str_list_push_front(struct hx_str_node* head, const char* data) {
    struct hx_str_node* node = (struct hx_str_node*)kmalloc(sizeof(struct hx_str_node), GFP_KERNEL);
    size_t n = strlen(data) + 1;
    char* str = (char *)kmalloc(sizeof(char) * n, GFP_KERNEL);
    strlcpy(str, data, n);
    node->next = head->next;
    head->next = node;
    node->data = str;
    node->n = n - 1;
}

// 清空链表
void hx_str_list_clear(struct hx_str_node* head) {
    struct hx_str_node* node = head->next;
    while (node) {
        kfree(node->data);
        struct hx_str_node* nx = node->next;
        kfree(node);
        node = nx;
    }
}

int hx_str_list_contains(struct hx_str_node* head, const char* data) {
    if (!data)
        return 0;
    struct hx_str_node* node = head->next;
    size_t n = strlen(data);
    for (; node; node = node->next) {
        if (node->n == n && strncmp(node->data, data, n) == 0) {
            // HX_LOG("contains: %s == %s", node->data, data);
            return 1;
        }
    }
    return 0;
}

int hx_config_load_process(void) {
    static struct file* fp;
    int err = hx_ensure_directory_exists("/hx/config", 0755);
    if (err < 0) {
        printk("open config dir, err = %d\n", err);
        return -1;
    }
    fp = filp_open("/hx/config/hx_file_p.config", O_RDONLY | O_CREAT, 0644);
    if (IS_ERR(fp)) {
        int ret = PTR_ERR(fp);
        printk("open config failed, err = %d\n", ret);
        return -1;
    }
    // 获取文件大小并分配缓冲区
    loff_t file_size = i_size_read(file_inode(fp));
    char *file_buf = kzalloc(file_size + 1, GFP_KERNEL);
    if (!file_buf) {
        printk("alloc memory failed\n");
        filp_close(fp, NULL);
        return -ENOMEM;
    }

    // 读取文件内容
    int read_bytes = kernel_read(fp, file_buf, file_size, &(loff_t){0});
    if (read_bytes < 0) {
        printk("read config failed, err (read_bytes) = %d\n", read_bytes);
        kfree(file_buf);
        filp_close(fp, NULL);
        return -1;
    }
    file_buf[read_bytes] = '\0';

    // 逐行解析文件路径
    char *line = file_buf;
    while (line && *line) {
        char *next_line = strchr(line, '\n');
        if (next_line) {
            *next_line = '\0';  // 替换换行符为字符串结束符
            next_line++;        // 移动到下一行
        }

        // 跳过空行和注释行(以#开头)
        if (*line == '\0' || *line == '#') {
            line = next_line;
            continue;
        }

        // 直接使用整行作为文件路径
        printk("loaded config - file path: %s\n", line);
        
        // 将文件路径添加到链表
        hx_str_list_push_front(&hx_process_list, line);
        
        line = next_line;  // 处理下一行
    }

    kfree(file_buf);
    filp_close(fp, NULL);
    return 0;
}

int hx_config_load_file(void) {
    static struct file* fp;
    int err = hx_ensure_directory_exists("/hx/config", 0755);
    if (err < 0) {
        printk("open config dir, err = %d\n", err);
        return -1;
    }
    fp = filp_open("/hx/config/hx_file_f.config", O_RDONLY | O_CREAT, 0644);
    if (IS_ERR(fp)) {
        int ret = PTR_ERR(fp);
        printk("open config failed, err = %d\n", ret);
        return -1;
    }
    // 获取文件大小并分配缓冲区
    loff_t file_size = i_size_read(file_inode(fp));
    char *file_buf = kzalloc(file_size + 1, GFP_KERNEL);
    if (!file_buf) {
        printk("alloc memory failed\n");
        filp_close(fp, NULL);
        return -ENOMEM;
    }

    // 读取文件内容
    int read_bytes = kernel_read(fp, file_buf, file_size, &(loff_t){0});
    if (read_bytes < 0) {
        printk("read config failed, err (read_bytes) = %d\n", read_bytes);
        kfree(file_buf);
        filp_close(fp, NULL);
        return -1;
    }
    file_buf[read_bytes] = '\0';

    // 逐行解析文件路径
    char *line = file_buf;
    while (line && *line) {
        char *next_line = strchr(line, '\n');
        if (next_line) {
            *next_line = '\0';  // 替换换行符为字符串结束符
            next_line++;        // 移动到下一行
        }

        // 跳过空行和注释行(以#开头)
        if (*line == '\0' || *line == '#') {
            line = next_line;
            continue;
        }

        // 直接使用整行作为文件路径
        printk("loaded config - file path: %s\n", line); // loaded config - file path: /home/loli/code/HX-LinuxMonitor/__tmp__c.md
        
        // 将文件路径添加到链表
        hx_str_list_push_front(&hx_file_list, line);
        
        line = next_line;  // 处理下一行
    }

    kfree(file_buf);
    filp_close(fp, NULL);
    return 0;
}

#define MAX_PATH 256
struct open_data {
    bool deny;
};

/* Entry handler: 决定是否拒绝，并在 data 中记录 */
static int open_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct open_data *data = (struct open_data *)ri->data;
    char user_path[MAX_PATH];

    /* 从 regs->si（filename）拷贝用户空间路径 */
    if (strncpy_from_user(user_path, (char __user *)regs->si, MAX_PATH) < 0) {
        data->deny = false;
        return 0;
    }
    user_path[MAX_PATH - 1] = '\0';

    char* file_path = NULL;
    char* allocated_full_path = NULL;
    char path_pwd_str[MAX_PATH]; // 当前工作目录
    // 处理文件的绝对路径与相对路径
    if (user_path[0] != '/') {
        struct path pwd;
        get_fs_pwd(current->fs, &pwd);
        char *cwd = d_path(&pwd, path_pwd_str, sizeof(path_pwd_str));
        if (!IS_ERR(cwd)) {
            allocated_full_path = kmalloc(PATH_MAX, GFP_ATOMIC);
            if (allocated_full_path) {
                snprintf(allocated_full_path, PATH_MAX, "%s/%s", cwd, user_path);
                file_path = hx_simplify_path(allocated_full_path);
            } else {
                HX_LOG("err: %s", user_path);
                file_path = user_path;
                kfree(allocated_full_path);
                allocated_full_path = NULL;
            }
        } else {
            HX_LOG("err: %s", user_path);
            file_path = user_path;
        }
    } else {
        file_path = user_path;
    }

    char exe_path[MAX_PATH];
    const char* comm = NULL;
    // 获取可执行文件路径
    if (current->mm && current->mm->exe_file) {
        char* exe_path_ptr = d_path(&current->mm->exe_file->f_path, exe_path, sizeof(exe_path));
        if (!IS_ERR(exe_path_ptr)) {
            comm = exe_path_ptr;
        }
    }

    // 判断是否处于白名单
    if (hx_str_list_contains(&hx_file_list, file_path)) {
        if (!hx_str_list_contains(&hx_process_list, comm)) {
            data->deny = true;
            // [触发时间] [触发进程(全路径)] [该进程操作对象(文件)] [该进程操作内容] [本程序处理结果]
            HX_LOG("程序 %s 尝试访问 %s 已拒绝\n", comm, file_path);
        }
#if 0 /* 此处记录是否需要 记录打开日志 */
        else {
            HX_LOG("程序 %s 尝试访问 %s 已允许\n", comm, file_path);
            data->deny = false;
        }
#endif
    } else {
        data->deny = false;
    }

    if (allocated_full_path) {
        kfree(allocated_full_path);
        kfree(file_path);
    }
    return 0;
}

/* Return handler：如果需要拒绝，就把返回值改为 -EACCES */
static int open_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct open_data *data = (struct open_data *)ri->data;
    if (data->deny) {
        regs->ax = -EACCES;
    }
    return 0;
}

static struct kretprobe openat_kret = {
    .handler        = open_ret,
    .entry_handler  = open_entry,
    .maxactive      = 20,
    .kp.symbol_name = "do_sys_open",
    .data_size      = sizeof(struct open_data),
};

static int __init kprobe_init(void) {
    int ret;
    if (hx_config_load_file() < 0) {
        printk("err: hx_config_load_file");
        return -1;
    }
    if (hx_config_load_process() < 0) {
        printk("err: hx_config_load_file");
        return -1;
    }
    if (hx_log_init("/hx/log", "hx_file.log") < 0) {
        printk("err: hx_log_init");
        return -1;
    }
    ret = register_kretprobe(&openat_kret);
    if (ret < 0) {
        printk(KERN_ERR "register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kretprobe(&openat_kret);
    hx_log_clone();
    printk(KERN_INFO "kprobe unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);
