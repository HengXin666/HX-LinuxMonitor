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
#ifndef _HX_HX_PATH_TOOLS_H_
#define _HX_HX_PATH_TOOLS_H_

#include <linux/slab.h>
#include <linux/string.h>

#define MAX_PARTS 256
#define MAX_PATH_LEN 512

// https://leetcode.cn/problems/simplify-path/

char* hx_simplify_path(const char *path) {
    char *p;
    char *stk[96];
    int top = 0;

    // 拷贝一份路径用于处理
    p = kstrdup(path, GFP_KERNEL);
    if (!p)
        return NULL;

    // 手动分割路径（类似 strtok）
    char *token = strsep(&p, "/");
    while (token) {
        if (strcmp(token, "..") == 0) {
            if (top > 0)
                top--;
        } else if (strcmp(token, ".") == 0 || token[0] == '\0') {
            // 忽略 '.' 和空段
        } else {
            stk[top++] = token;
        }
        token = strsep(&p, "/");
    }

    // 空路径表示根目录
    if (top == 0) {
        kfree(p); // 注意，这里仍然释放，因为 strsep 修改了原始 p 的指针位置
        return kstrdup("/", GFP_KERNEL);
    }

    // 拼接结果路径
    char *result = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
    if (!result) {
        kfree(p);
        return NULL;
    }

    char *q = result;
    int remain = MAX_PATH_LEN;
    for (int i = 0; i < top; ++i) {
        int written = scnprintf(q, remain, "/%s", stk[i]);
        q += written;
        remain -= written;
        if (remain <= 0)
            break; // 超出限制
    }

    *q = '\0';
    kfree(p);
    return result;
}

#endif // !_HX_HX_PATH_TOOLS_H_