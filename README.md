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