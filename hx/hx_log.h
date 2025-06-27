#pragma once
/*
 * Copyright (C) 2025 Heng_Xin. All rights reserved.
 *
 * This file is part of HX-LinuxMonitor.
 *
 * HX-LinuxMonitor is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * HX-LinuxMonitor is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with HX-LinuxMonitor.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef _HX_HX_LOG_H_
#define _HX_HX_LOG_H_

#include "hx_dir_tools.h"

static struct file* hx_log_fp;
static DEFINE_SPINLOCK(hx_log_lock); // 定义全局锁

int hx_log_init(void) {
    // 在hx_log_init中添加目录创建
    int err = hx_ensure_directory_exists("/home/kylin/.log", 0755);
    if (err < 0) {
        printk("open log dir, err = %d\n", err);
        return -1;
    }
    hx_log_fp = filp_open("/home/kylin/.log/hx.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
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

// @todo 读写有问题... 还是会竞争然后卡死
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
    char buf[476] = {0};
    char msg[476] = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    ktime_t kt = ktime_get_real(); // 获取 UTC 时间
    struct timespec64 ts = ktime_to_timespec64(kt);
    struct tm tm;

    ts.tv_sec += 8 * 60 * 60; // UTC+8
    time64_to_tm(ts.tv_sec, 0, &tm);

    snprintf(msg, sizeof(msg), "[%04ld-%02d-%02d %02d:%02d:%02d]: %s",
        tm.tm_year + 1900L, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec, buf);

    // 同时写入内核日志和自定义文件
    printk("%s", msg);    // 内核日志
    // hx_log(msg);          // 自定义文件
}
#endif

#endif // !_HX_HX_LOG_H_