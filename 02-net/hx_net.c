#include "../hx/hx_linux_inc.h"
#include "../hx/hx_log.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A hx_net Module");

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

int hx_config_load(void) {
    static struct file* fp;
    int err = hx_ensure_directory_exists("/hx/config", 0755);
    if (err < 0) {
        printk("open log dir, err = %d\n", err);
        return -1;
    }
    fp = filp_open("/hx/config/hx_net_url.config", O_RDONLY | O_CREAT, 0644);
    if (IS_ERR(fp)) {
        int ret = PTR_ERR(fp);
        printk("open log failed, err = %d\n", ret);
        return -1;
    }
    // 解析, 按照 : 分割 (ip:端口)
    // 读取整个文件内容
    loff_t file_size = i_size_read(file_inode(fp));
    char *file_buf = kzalloc(file_size + 1, GFP_KERNEL);
    if (!file_buf) {
        printk("alloc memory failed\n");
        filp_close(fp, NULL);
        return -ENOMEM;
    }

    // mm_segment_t old_fs = get_fs();
    // set_fs(KERNEL_DS);
    int read_bytes = kernel_read(fp, file_buf, file_size, &(loff_t){0});
    // set_fs(old_fs);
    
    if (read_bytes < 0) {
        printk("read config failed, err (read_bytes) = %d\n", read_bytes);
        kfree(file_buf);
        filp_close(fp, NULL);
        return -1;
    }
    file_buf[read_bytes] = '\0';

    // 逐行解析
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

        // 解析ip:port
        char *ip = line;
        char *port_str = strchr(line, ':');
        if (!port_str) {
            printk("无效的配置格式，行中缺少 ':': %s\n", line); // 表示为该ip下任意端口
            line = next_line;
            hx_addr_list_push_front(make_hx_addrinfo(ip, 0));
            continue;
        }
        
        *port_str = '\0';  // 分隔ip和port
        port_str++;
        
        // 转换端口号
        unsigned short port;
        if (kstrtou16(port_str, 10, &port)) {
            printk("行中的端口号无效: %s\n", line);
            line = next_line;
            continue;
        }

        printk("loaded config - ip: %s, port: %d\n", ip, port);
        
        hx_addr_list_push_front(make_hx_addrinfo(ip, port));
        
        line = next_line;  // 处理下一行
    }

    kfree(file_buf);
    filp_close(fp, NULL);
    return 0;
}

int hx_is_work_time(void) {
    return 1;
}

static struct nf_hook_ops out_nfho; // net filter hook option struct

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
                // 如果目标 ip:端口 是黑名单内容, 则禁止
                // @todo 判断上班时间区间
                if (hx_is_work_time() && hx_addr_list_contains(nh->daddr, th->dest)) {
                    if (current->mm) {
                        HX_LOG("程序 %s 尝试访问 %u.%u.%u.%u:%d 已拦截\n", 
                            d_path(&current->mm->exe_file->f_path, path, PATH_STR_LEN_MAX), // 程序所在全路径
                            NIPQUAD(nh->daddr), ntohs(th->dest)       // 目标ip - 端口
                        );
                    }
                    return NF_DROP;
                } 
                // else {
                //     HX_LOG("[PASS-TCP] %u.%u.%u.%u:%d (pid = %u, src = %s) -> %u.%u.%u.%u:%d\n", 
                //         NIPQUAD(nh->saddr), ntohs(th->source),     // 源ip - 端口
                //         task_pid_nr(current),                      // pid 
                //         current->mm 
                //             ? d_path(&current->mm->exe_file->f_path, path, PATH_STR_LEN_MAX) // 程序所在全路径
                //             : "null",
                //         NIPQUAD(nh->daddr), ntohs(th->dest)       // 目标ip - 端口
                //     );
                // }
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr* uh = udp_hdr(skb);
                char path[PATH_STR_LEN_MAX] = {0};
                if (hx_is_work_time() && hx_addr_list_contains(nh->daddr, uh->dest)) {
                    if (current->mm) {
                        HX_LOG("程序 %s 尝试访问 %u.%u.%u.%u:%d 已拦截\n", 
                            d_path(&current->mm->exe_file->f_path, path, PATH_STR_LEN_MAX), // 程序所在全路径
                            NIPQUAD(nh->daddr), ntohs(uh->dest)       // 目标ip - 端口
                        );
                    }
                    return NF_DROP;
                }
                // else {
                //     HX_LOG("[PASS-UDP] %u.%u.%u.%u:%d (pid = %u, src = %s) -> %u.%u.%u.%u:%d\n", 
                //         NIPQUAD(nh->saddr), ntohs(uh->source),     // 源ip - 端口
                //         task_pid_nr(current),                      // pid 
                //         current->mm 
                //             ? d_path(&current->mm->exe_file->f_path, path, PATH_STR_LEN_MAX) // 程序所在全路径
                //             : "null",
                //         NIPQUAD(nh->daddr), ntohs(uh->dest)       // 目标ip - 端口
                //     );
                // }
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
    
    if (hx_config_load() < 0) {
        printk("error config init");
        return -1;
    }
    printk("run hx_net...\n");
    if (hx_log_init("/hx/log", "hx_net.log") < 0) {
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
    printk(KERN_INFO "hx_net exit\n");
}

module_init(init_func);
module_exit(exit_func);
