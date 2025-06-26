#include <linux/module.h> // included for all kernel modules
#include <linux/kernel.h> // included for KERN_INFO
#include <linux/init.h>   // included for __init and __exit macros
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/init_task.h> // init_user_ns
#include <linux/dcache.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A Simple Hello Packet Module");

// 文件 io
#define HX_LOG_FILE_PATH "/home/kylin/.log/HX-LinuxMonitor.log"

static struct file* hx_log_fp;
static DEFINE_SPINLOCK(hx_log_lock); // 定义全局锁

int hx_ensure_directory_exists(const char *dir_path, umode_t mode) {
    char *path_buf, *p;
    int ret = 0;

    // 拷贝路径，防止修改原始字符串
    path_buf = kstrdup(dir_path, GFP_KERNEL);
    if (!path_buf)
        return -ENOMEM;

    // 忽略前导 '/'
    if (path_buf[0] == '/')
        p = path_buf + 1;
    else
        p = path_buf;

    while (1) {
        char *next = strchr(p, '/');
        if (next)
            *next = '\0';

        char *partial_path = kasprintf(GFP_KERNEL, "/%s", path_buf);
        if (!partial_path) {
            ret = -ENOMEM;
            break;
        }

        struct path path;
        ret = kern_path(partial_path, LOOKUP_DIRECTORY, &path);
        if (ret != 0) {
            // 不存在则尝试创建
            struct path parent_path;
            struct dentry *dentry;
            dentry = kern_path_create(AT_FDCWD, partial_path, &parent_path, 0);
            if (IS_ERR(dentry)) {
                ret = PTR_ERR(dentry);
                kfree(partial_path);
                break;
            }

            ret = vfs_mkdir(d_inode(parent_path.dentry), dentry, mode);
            done_path_create(&parent_path, dentry);
        } else {
            path_put(&path); // 已存在
        }

        kfree(partial_path);

        if (!next)
            break;

        *next = '/'; // 还原路径分隔符
        p = next + 1;
        if (*p == '\0') // 如果路径结尾是 '/', 则终止
            break;
    }

    kfree(path_buf);
    return ret;
}

int hx_log_init(void) {
    // 在hx_log_init中添加目录创建
    int err = hx_ensure_directory_exists("/home/kylin/.log", 0755);
    if (err < 0) {
        printk("open log dir, err = %d\n", err);
        return -1;
    }
    hx_log_fp = filp_open("/home/kylin/.log/hx.log", O_WRONLY | O_CREAT, 0644);
    if (IS_ERR(hx_log_fp)) {
        int ret = PTR_ERR(hx_log_fp);
        printk("open log failed, err = %d\n", ret);
        return -1;
    }
    return 0;
}

int hx_log_clone(void) {
    return filp_close(hx_log_fp, NULL);
}

void hx_log(const char* msg) {
    // mm_segment_t old_fs;
    
    // 保存当前FS设置
    // old_fs = get_fs();
    
    // 设置内核空间访问权限
// #if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
//     set_fs(KERNEL_DS);
// #else
//     // 5.10+ 使用新的API
//     set_fs(USER_DS); // 实际5.10+不需要特别处理 (?)
// #endif

    // 写入文件
    loff_t pos = 0;
    size_t len = strlen(msg);

    spin_lock(&hx_log_lock);

    pos = hx_log_fp->f_pos;
    kernel_write(hx_log_fp, msg, len, &pos);
    hx_log_fp->f_pos = pos;

    spin_unlock(&hx_log_lock);

    // 恢复FS设置
// #if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
//     set_fs(old_fs);
// #endif
}

#if 0
#define HX_LOG(__STR__, ...)                                   \
    do {                                                       \
        char _hx_msg_#__LINE__[64] = {0};                      \
        vsprintf(_hx_msg_#__LINE__,  __STR__, ##__VA_ARGS__);  \
        hx_log(_hx_msg_#__LINE__);                             \
    } while (0)
#else
void HX_LOG(const char *fmt, ...) {
    char buf[256] = {0};  // 增加缓冲区大小
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args); // 使用更安全的vsnprintf
    va_end(args);
    
    // 同时写入内核日志和自定义文件
    printk("%s", buf);    // 内核日志
    hx_log(buf);          // 自定义文件
}
#endif

// 可存储 ipv4/ipv6 - 端口 的数据结构
struct hx_addrinfo {
    __be32 addr;
    uint16_t port;  // 如果是 0, 则表示任意端口, (存储为网络序, 由 make_hx_addrinfo 维护)
                    // 因为 tcp_hdr 中得到的都是网络序的, 那我只需要从主机序转为网络序, 之后就不用转了
};

struct hx_addrinfo* make_hx_addrinfo(const char* src, uint16_t port) {
    struct hx_addrinfo* res = (struct hx_addrinfo*)kmalloc(sizeof(struct hx_addrinfo), GFP_KERNEL);
    res->addr = in_aton(src);
    res->port = ntohs(port);
    return res;
}

struct hx_addr_node {
    struct hx_addrinfo* data;
    struct hx_addr_node* next;
};

static struct hx_addr_node hx_addr_list;

// 头插法
void hx_addr_list_push_front(struct hx_addrinfo* data) {
    struct hx_addr_node* node = (struct hx_addr_node*)kmalloc(sizeof(struct hx_addr_node), GFP_KERNEL);
    node->next = hx_addr_list.next;
    hx_addr_list.next = node;
    node->data = data;
}

// 清空链表
void hx_addr_list_clear(void) {
    struct hx_addr_node* node = hx_addr_list.next;
    while (node) {
        kfree(node->data);
        struct hx_addr_node* nx = node->next;
        kfree(node);
        node = nx;
    }
}

// 该ip:端口 是否在 黑名单 中
int hx_addr_list_contains(__be32 addr, uint16_t port) {
    struct hx_addr_node* node = hx_addr_list.next;
    for (; node; node = node->next) {
        if (node->data->addr == addr 
            && (node->data->port == port || !node->data->port)
        ) {
            return 1;
        }
    }
    return 0;
}

static struct nf_hook_ops out_nfho; // net filter hook option struct

void __info_path_test(void) {
    /*
    [  384.550951] current path = 桌面
    [  384.550952] root path = /
    [  384.550953] task_path_1 = /home/kylin/hx/cmake/firefox/firefox-bin
    [  384.550954] task_path_2 = /home/kylin/hx/cmake/firefox/firefox-bin
    */
   struct qstr root_task_path;
   struct qstr current_task_path;
   
#define TASK_PATH_MAX_LENGTH 64
    char buf_1[TASK_PATH_MAX_LENGTH] = {0};
    char *task_path_1 = NULL;

    char buf_2[TASK_PATH_MAX_LENGTH] = {0};
    char *task_path_2 = NULL;

	//获取当前目录名
    current_task_path = current->fs->pwd.dentry->d_name;
    //获取根目录
    root_task_path = current->fs->root.dentry->d_name;

	//内核线程的 mm 成员为空，这里没做判断
    if (!current->mm) {
        printk("null: mm");
        return;
    }
	
    //2.6.32 没有dentry_path_raw API
    //获取文件全路径
    task_path_1 = dentry_path_raw(current->mm->exe_file->f_path.dentry, buf_1, TASK_PATH_MAX_LENGTH);

	//获取文件全路径
	//调用d_path函数文件的路径时，应该使用返回的指针：task_path_2 ，而不是转递进去的参数buf：buf_2
    task_path_2 = d_path(&current->mm->exe_file->f_path, buf_2, TASK_PATH_MAX_LENGTH);
    if (IS_ERR(task_path_2)) {
        printk("Get path failed\n");
        return;
    }

    printk("current path = %s\n", current_task_path.name);
    printk("root path = %s\n", root_task_path.name);
    printk("task_path_1 = %s\n", task_path_1);
    printk("task_path_2 = %s\n", task_path_2);

#undef TASK_PATH_MAX_LENGTH
}

unsigned int hook_sent_request(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
#define PATH_STR_LEN_MAX 96
#define NIPQUAD(addr) ((unsigned char *)&addr)[0], \
                      ((unsigned char *)&addr)[1], \
                      ((unsigned char *)&addr)[2], \
                      ((unsigned char *)&addr)[3]

    // 如果是ip协议
    if ((skb->protocol) == htons(ETH_P_IP)) {
        struct iphdr* nh = ip_hdr(skb);
        // printk("src: %u.%u.%u.%u, dst: %u.%u.%u.%u\n", NIPQUAD(nh->saddr), NIPQUAD(nh->daddr));
        switch (nh->protocol) {
            case IPPROTO_TCP: {
                struct tcphdr* th = tcp_hdr(skb);
                // src: 192.168.0.202, sport: 57572 dst: 121.36.16.180 dport: 47873
                char path[PATH_STR_LEN_MAX] = {0};
                HX_LOG("[TCP] %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d (%u @ %s) [addr: %u]\n", 
                    NIPQUAD(nh->saddr), ntohs(th->source),     // 源ip - 端口
                    NIPQUAD(nh->daddr), ntohs(th->dest),       // 目标ip - 端口
                    task_pid_nr(current),                      // pid 
                    current->mm 
                        ? d_path(&current->mm->exe_file->f_path, path, PATH_STR_LEN_MAX) // 程序所在全路径
                        : "",
                    nh->daddr
                );
                // 如果目标 ip:端口 是黑名单内容, 则禁止
                if (hx_addr_list_contains(nh->daddr, th->dest)) {
                    HX_LOG("[Hook TCP] === %u.%u.%u.%u:%d\n", NIPQUAD(nh->daddr), ntohs(th->dest));
                    return NF_DROP;
                }
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr* uh = udp_hdr(skb);
                HX_LOG("[UDP] %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d\n", 
                    NIPQUAD(nh->saddr), ntohs(uh->source), // 源ip - 端口
                    NIPQUAD(nh->daddr), ntohs(uh->dest));  // 目标ip - 端口
                // 如果目标 ip:端口 是黑名单内容, 则禁止
                if (hx_addr_list_contains(nh->daddr, uh->dest)) {
                    printk("[Hook UDP] === %u.%u.%u.%u:%d\n", NIPQUAD(nh->daddr), ntohs(uh->dest));
                    return NF_DROP;
                }
                break;
            }
            case IPPROTO_IPV6: {
                printk("[IPv6]"); // @todo https://wenku.csdn.net/answer/6noibmz8jq
                break;
            }
            default: {
                break;
            }
        }
    }

    return NF_ACCEPT;

#undef NIPQUAD
#undef PATH_STR_LEN_MAX
}

static int __init init_func(void) {
    /* from: https://zhuanlan.zhihu.com/p/81866818
    --->[NF_IP_PRE_ROUTING]--->[ROUTE]--->[NF_IP_FORWARD]--->[NF_IP_POST_ROUTING]--->
                              |                        ^
                              |                        |
                              |                     [ROUTE]
                              v                        |
                       [NF_IP_LOCAL_IN]        [NF_IP_LOCAL_OUT]
                              |                        ^
                              |                        |
                              v                        |
    NF_IP_PRE_ROUTING: 位于路由之前，报文一致性检查之后（报文一致性检查包括: 报文版本、报文长度和checksum）。
    NF_IP_LOCAL_IN: 位于报文经过路由之后，并且目的是本机的。
    NF_IP_FORWARD：位于在报文路由之后，目的地非本机的。
    NF_IP_LOCAL_OUT: 由本机发出去的报文，并且在路由之前。
    NF_IP_POST_ROUTING: 所有即将离开本机的报文。
    */
    // NF_IP_LOCAL_OUT hook
    out_nfho.hook = hook_sent_request;
    out_nfho.hooknum = NF_INET_LOCAL_OUT;
    out_nfho.pf = PF_INET;
    out_nfho.priority = NF_IP_PRI_FIRST;
    
    // http://143.244.210.202:443/
    hx_addr_list_push_front(make_hx_addrinfo("143.244.210.202", 443));
    
    printk("run ...\n");
    if (hx_log_init() < 0) {
        printk("error log init");
        return -1;
    }
    nf_register_net_hook(&init_net, &out_nfho);
    return 0;
}

static void __exit exit_func(void) {
    nf_unregister_net_hook(&init_net, &out_nfho);
    hx_addr_list_clear();
    hx_log_clone();
    printk(KERN_INFO "Cleaning up Hello_Packet module.\n");
}

module_init(init_func);
module_exit(exit_func);
