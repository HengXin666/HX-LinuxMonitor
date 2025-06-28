#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include "../hx/hx_dir_tools.h"
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

    /* 这里可以加更复杂的白名单/黑名单判断 */
    if (hx_str_list_contains(&hx_file_list, user_path) &&
        !hx_str_list_contains(&hx_process_list, current->comm)) {
        data->deny = true;
        HX_LOG("拦截: %s %s", user_path, current->comm);
    } else {
        data->deny = false;
    }
    return 0;
}

/* Return handler：如果需要拒绝，就把返回值改为 -EACCES */
static int open_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct open_data *data = (struct open_data *)ri->data;
    if (data->deny) {
        regs->ax = -EACCES;
        HX_LOG("进行拦截");
    }
    return 0;
}

static struct kretprobe openat_kret = {
    .handler        = open_ret,
    .entry_handler  = open_entry,
    .maxactive      = 20,
    .kp.symbol_name = "do_sys_open",   // 或者 "do_sys_open"
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

/* 过滤掉的:
[ 7334.319110] PID 75093 (cat) try open file: ko.c
[ 7334.319114] Intercepted open .c file: ko.c
[ 7334.319160] general protection fault, maybe for address 0x7ffffe95b119: 0000 [#17] SMP PTI
[ 7334.319165] CPU: 1 PID: 75093 Comm: cat Tainted: G      D    OE     5.10.0-18-generic #1~v10pro-KYLINOS
[ 7334.319169] Hardware name: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 11/12/2020
[ 7334.319175] RIP: 0010:do_sys_open+0x1/0x80
[ 7334.319179] Code: e8 c4 58 01 00 4c 89 e8 5b 41 5c 41 5d 5d c3 cc cc cc cc 49 89 c5 5b 41 5c 4c 89 e8 41 5d 5d c3 cc cc cc cc 0f 1f 44 00 00 e8 <1b> 8e 0a 25 55 48 89 e5 48 83 ec 20 65 48 8b 04 25 28 00 00 00 48
[ 7334.319183] RSP: 0018:ffffaa4745debf28 EFLAGS: 00010282
[ 7334.319187] RAX: fffffffffffffff3 RBX: 0000000000000000 RCX: 0000000000000000
[ 7334.319191] RDX: 0000000000008000 RSI: 00007ffffe95b119 RDI: 00000000ffffff9c
[ 7334.319194] RBP: ffffaa4745debf30 R08: 0000000000000101 R09: 0000000000000000
[ 7334.319198] R10: 0000000000000001 R11: 000000002587f9f0 R12: ffffaa4745debf58
[ 7334.319202] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[ 7334.319205] FS:  00007ff17c1b7580(0000) GS:ffff9ca275e40000(0000) knlGS:0000000000000000
[ 7334.319209] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 7334.319213] CR2: 00007ff17c0c9600 CR3: 0000000112dbe002 CR4: 0000000000370ee0
[ 7334.319217] Call Trace:
[ 7334.319222]  ? __x64_sys_openat+0x20/0x30
[ 7334.319227]  do_syscall_64+0x35/0x90
[ 7334.319232]  entry_SYSCALL_64_after_hwframe+0x61/0xc6
[ 7334.319236] RIP: 0033:0x7ff17c0d4f8b
[ 7334.319240] Code: 25 00 00 41 00 3d 00 00 41 00 74 4b 64 8b 04 25 18 00 00 00 85 c0 75 67 44 89 e2 48 89 ee bf 9c ff ff ff b8 01 01 00 00 0f 05 <48> 3d 00 f0 ff ff 0f 87 91 00 00 00 48 8b 4c 24 28 64 48 33 0c 25
[ 7334.319244] RSP: 002b:00007ffffe95a370 EFLAGS: 00000246 ORIG_RAX: 0000000000000101
[ 7334.319248] RAX: ffffffffffffffda RBX: 000056201c84063c RCX: 00007ff17c0d4f8b
[ 7334.319251] RDX: 0000000000000000 RSI: 00007ffffe95b119 RDI: 00000000ffffff9c
[ 7334.319255] RBP: 00007ffffe95b119 R08: 0000000000000001 R09: 0000000000000000
[ 7334.319258] R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
[ 7334.319262] R13: 00007ffffe95a650 R14: 0000000000020000 R15: 0000000000000000
[ 7334.319266] Modules linked in: ko(OE) xt_comm(OE) bnep bluetooth ecdh_generic ecc nls_utf8 isofs st xt_multiport ipt_REJECT nf_reject_ipv4 xt_conntrack nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 libcrc32c iptable_filter vsock_loopback vmw_vsock_virtio_transport_common vmw_vsock_vmci_transport vsock vmw_balloon crct10dif_pclmul crc32_pclmul ghash_clmulni_intel snd_ens1371 snd_ac97_codec gameport ac97_bus snd_pcm joydev snd_seq_midi snd_seq_midi_event snd_rawmidi snd_seq snd_seq_device snd_timer snd soundcore e1000 vmw_vmci i2c_piix4 ky_dlp(OE) hwmon_vid parport_pc ppdev lp parport ramoops reed_solomon efi_pstore ip_tables x_tables autofs4 multipath linear aesni_intel glue_helper crypto_simd cryptd input_leds psmouse serio_raw vmwgfx ttm drm_kms_helper syscopyarea sysfillrect sysimgblt fb_sys_fops cec ahci libahci mptspi drm mptscsih mptbase scsi_transport_spi pata_acpi mac_hid hid_generic usbhid hid [last unloaded: ko]
[ 7334.319296] ---[ end trace 6f1537367641b12e ]---
[ 7334.319301] RIP: 0010:do_sys_open+0x1/0x80
[ 7334.319305] Code: e8 c4 58 01 00 4c 89 e8 5b 41 5c 41 5d 5d c3 cc cc cc cc 49 89 c5 5b 41 5c 4c 89 e8 41 5d 5d c3 cc cc cc cc 0f 1f 44 00 00 e8 <1b> 8e 0a 25 55 48 89 e5 48 83 ec 20 65 48 8b 04 25 28 00 00 00 48
[ 7334.319308] RSP: 0018:ffffaa4743cf7f28 EFLAGS: 00010282
[ 7334.319312] RAX: fffffffffffffff3 RBX: 0000000000000000 RCX: 0000000000000000
[ 7334.319315] RDX: 0000000000008000 RSI: 00007ffd0477135a RDI: 00000000ffffff9c
[ 7334.319319] RBP: ffffaa4743cf7f30 R08: 0000000000000101 R09: 0000000000000000
[ 7334.319323] R10: 0000000000000001 R11: 0000000021cf9e60 R12: ffffaa4743cf7f58
[ 7334.319326] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[ 7334.319330] FS:  00007ff17c1b7580(0000) GS:ffff9ca275e40000(0000) knlGS:0000000000000000
[ 7334.319333] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 7334.319337] CR2: 00007ff17c0c9600 CR3: 0000000112dbe002 CR4: 0000000000370ee0
*/
