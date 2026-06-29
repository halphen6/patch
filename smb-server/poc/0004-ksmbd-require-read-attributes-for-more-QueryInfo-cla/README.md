# patch-09: ksmbd QueryInfo missing FILE_READ_ATTRIBUTES checks

结论：当前树中该问题真实存在。

受影响路径：

- `server/smb2pdu.c:get_file_standard_info()`
- `server/smb2pdu.c:get_file_internal_info()`
- `server/smb2pdu.c:get_file_compression_info()`

这些 `SMB2 QUERY_INFO / SMB2_O_INFO_FILE` 处理器在返回文件大小、分配大小、链接数、inode 号、压缩大小等元数据前没有校验当前句柄的
`fp->daccess & FILE_READ_ATTRIBUTES_LE`。同一文件中多个兄弟处理器已经做了该检查，包括
`get_file_basic_info()`、`get_file_all_info()`、`get_file_network_open_info()`、`get_file_attribute_tag_info()` 和
`find_file_posix_info()`。

本包内容：

- `poc_ksmbd_query_info_read_attrs.py`: 纯 Python SMB2 PoC。使用 write-only 句柄发送精确的 `QUERY_INFO` 请求。
- `OPERATION_MANUAL.md`: 隔离实验环境中的复现步骤。
- `VULN_ANALYSIS.md`: 针对当前源码的代码路径分析。

快速运行：

```sh
python3 poc_ksmbd_query_info_read_attrs.py 127.0.0.1 poc test.bin -u guest
```

漏洞存在时，PoC 的关键特征是：

- `FILE_BASIC_INFORMATION` 返回 `STATUS_ACCESS_DENIED`，说明 write-only 句柄确实不含 `FILE_READ_ATTRIBUTES`。
- `FILE_STANDARD_INFORMATION`、`FILE_INTERNAL_INFORMATION` 或 `FILE_COMPRESSION_INFORMATION` 至少一个返回 `STATUS_SUCCESS`。

PoC 默认使用 guest/anonymous NTLMSSP 形态，适合本地 ksmbd 实验 share。该授权缺陷不依赖 guest；guest 只是为了让 PoC 不依赖外部 SMB 库和完整 NTLMv2 密码认证实现。
