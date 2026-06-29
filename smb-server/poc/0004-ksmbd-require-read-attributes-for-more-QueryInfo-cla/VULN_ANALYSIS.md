# Vulnerability Analysis

## Summary

`server/smb2pdu.c` 中三个 `SMB2 QUERY_INFO` 文件信息处理器缺少每句柄 `FILE_READ_ATTRIBUTES_LE` 授权检查：

- `get_file_standard_info()`
- `get_file_internal_info()`
- `get_file_compression_info()`

攻击者使用只授予 `FILE_WRITE_DATA_LE` 的打开句柄后，仍可通过这些 info class 读取文件元数据。

## Code Evidence

`get_file_basic_info()` 在读取 stat 元数据前执行：

```c
if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE))
	return -EACCES;
```

`get_file_all_info()`、`get_file_network_open_info()`、`get_file_attribute_tag_info()` 和 HEAD 中已修复的
`find_file_posix_info()` 都有同类 gate。

但以下三个函数没有同类检查：

```c
static int get_file_standard_info(...)
{
	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
			  AT_STATX_SYNC_AS_STAT);
	...
	sinfo->AllocationSize = ...
	sinfo->EndOfFile = ...
	sinfo->NumberOfLinks = ...
}
```

```c
static int get_file_internal_info(...)
{
	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
			  AT_STATX_SYNC_AS_STAT);
	...
	file_info->IndexNumber = cpu_to_le64(stat.ino);
}
```

```c
static int get_file_compression_info(...)
{
	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
			  AT_STATX_SYNC_AS_STAT);
	...
	ret = ksmbd_vfs_get_compression(fp, &fmt);
	...
	file_info->CompressedFileSize = ...
}
```

`smb2_get_info_file()` 根据 `req->FileInfoClass` 直接分发到各 helper，没有统一的 `FILE_READ_ATTRIBUTES_LE` 检查。因此授权判断完全依赖每个 helper 自己实现。

## Strong Corroborating Commit

当前 HEAD 已包含：

```text
20c8442dc100 ksmbd: enforce FILE_READ_ATTRIBUTES on SMB_FIND_FILE_POSIX_INFORMATION
```

该提交为 `find_file_posix_info()` 添加了同类检查。提交说明中的模型是：只用 `FILE_WRITE_DATA` 打开的句柄会被
`FileBasicInformation` 正确拒绝，却能读取更大的 POSIX 元数据集合。

三个遗漏处理器与该模式一致：同一 write-only 句柄被 `FILE_BASIC_INFORMATION` 拒绝，但仍可读取标准信息、内部信息或压缩信息。

## Impact

已建立 SMB 会话并能获得目标文件 write-only 句柄的客户端，可绕过每句柄访问掩码粒度读取文件元数据：

- 文件大小和分配大小
- hard link 数量
- delete pending 和 directory 标志
- inode/index number
- 压缩大小与压缩格式

这不是内存破坏，也不会导致服务崩溃；影响属于认证后授权绕过和信息泄露，严重度适合评为 Medium 或 Low-Medium。

## Expected Fix Shape

在三个 helper 开头、任何 `vfs_getattr()` 或 `ksmbd_vfs_get_compression()` 前加入与兄弟处理器一致的检查：

```c
if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE)) {
	pr_err("no right to read the attributes : 0x%x\n", fp->daccess);
	return -EACCES;
}
```

也可以考虑在 `smb2_get_info_file()` 中集中 gate 需要读取属性的 info class，但要避免误伤 `FILE_ACCESS_INFORMATION`、`FILE_POSITION_INFORMATION` 等不需要该权限的查询。
