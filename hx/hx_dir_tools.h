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
#ifndef _HX_HX_DIR_TOOLS_H_
#define _HX_HX_DIR_TOOLS_H_

#include "hx_linux_inc.h"

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

#endif // !_HX_HX_DIR_TOOLS_H_