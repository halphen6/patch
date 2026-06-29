# patch-08: ksmbd FSCTL_DUPLICATE_EXTENTS_TO_FILE credential-context check

结论：当前树中该问题存在。

证据：

- `server/smb2pdu.c` 的 `FSCTL_DUPLICATE_EXTENTS_TO_FILE` 分支在完成 share writable、目标 `FILE_WRITE_DATA`、源 `FILE_READ_DATA` 检查后，直接调用 `vfs_clone_file_range()`；当 clone 没有完整复制时，又直接调用 `vfs_copy_file_range()`。
- 该分支周围没有 `override_creds(fp_in->filp->f_cred)`、`override_creds(fp_out->filp->f_cred)` 或对应的 `revert_creds()`。
- HEAD 已包含 `c6394bcaf254`，该提交只给 `SET_SPARSE`、`SET_ZERO_DATA`、`SET_COMPRESSION` 这类单句柄 FSCTL 加了 opener credential 包裹，没有覆盖这个双句柄 duplicate-extents 分支。
- `server/vfs.c:1731` 的 `ksmbd_vfs_copy_file_ranges()` 也在调用 `vfs_copy_file_range()` 时缺少 opener credential 包裹，但本包重点验证 `FSCTL_DUPLICATE_EXTENTS_TO_FILE`。

影响：

- 已认证 SMB 客户端只要能获得合法源/目标句柄并满足 SMB 层访问掩码，就可触发服务端 VFS clone/copy。
- `vfs_clone_file_range()` 和 fallback `vfs_copy_file_range()` 会进入 `security_file_permission()` 等重新校验路径；当前实现让这些校验运行在 ksmbd worker 的 `current_cred()` 下，通常是 root，而不是打开 SMB 句柄时捕获到的 `file->f_cred`。
- 普通 DAC 场景不一定总能直接表现为数据越权；最稳定的验证方式是配合 LSM、audit、bpftrace 或内核探针确认进入 VFS helper 时的 `current` 凭据。

文件：

- `ksmbd_dup_extents_poc.c`: 用户态触发器。对 CIFS 挂载点上的目标文件执行 `FICLONERANGE`，Linux CIFS 客户端会发送 `FSCTL_DUPLICATE_EXTENTS_TO_FILE`。
- `trace_ksmbd_dup_extents.bt`: 服务端观察脚本，打印进入 `vfs_clone_file_range()` / `vfs_copy_file_range()` 时的 `comm/pid/uid/gid`。
- `OPERATIONS.md`: 本地实验操作手册。

修复方向：

- duplicate-extents 路径需要像 `c6394bcaf254` 修复的单文件 FSCTL 一样，在执行会重新校验权限/LSM 的 VFS helper 前切换到 opener credentials。
- 因为该 FSCTL 涉及源和目标两个句柄，修复时还要明确处理两个句柄 opener credential 不一致的情况；不能简单把整个 `smb2_ioctl()` 统一包在单一 session cred 下。
