# MMKV 文件格式

每个 MMKV 实例通常对应一对文件：

| 文件 | 说明 |
|------|------|
| `<id>` | 数据文件（mmap，常为 4KiB 对齐扩展） |
| `<id>.crc` | 元数据账本（一页内，热路径可只更新 CRC + ActualSize） |

## 数据文件布局

```
偏移 0          4                    8                     ActualSize+4
┌───────────────┬────────────────────┬─────────────────────┬──────────┐
│ actualSize    │ ItemSizeHolder     │ KV record …         │ free     │
│ uint32 LE (4) │ varint，占位约 4B  │ key + value 重复    │ padding  │
└───────────────┴────────────────────┴─────────────────────┴──────────┘
```

- **actualSize**：有效载荷长度（从偏移 4 起算）。旧版以文件头为准；有 `.crc` 且 meta 版本 ≥ `MMKVVersionActualSize`（3）时，以 meta 中的 `m_actualSize` 为准。
- **ItemSizeHolder**：历史字段曾表示 map 大小；现行实现写入随机伪装长度（`randomItemSizeHolder`），解码时先读掉再解析 KV。本包在 `NewMMKVReader` 内跳过该字段。
- **KV record**：追加写；同一 key 多次写入时后写覆盖先写；`value` 长度为 0 表示删除（本包的 `ReadStringValue` 对空 container 返回空字符串）。

加密时：文件头 4 字节 `actualSize` **不加密**；其后载荷（含 ItemSizeHolder 与 KV）使用 **AES-128-CFB**，IV 存在 `.crc` 的 `m_vector`。

## Key / Value 编码

均为 Protobuf 风格长度前缀：

```
String    = varint(len) || utf-8 bytes
Container = varint(len) || payload[len]

记录: String(key) || Container(value)
```

字符串值常见形态（本包 `ReadStringValue`）：

```
Container(
  String(utf-8)
)
```

整数等其它类型可直接落在 container 的 payload 里（varint / fixed 等）；可用 `ReadInt` / `ReadBytes` / `SkipContainer` 按需处理。

## `.crc` 元数据文件（`MMKVMetaInfo`）

按字段顺序落盘（小端）。结构须 ≤ 一页（通常 4KiB），便于单页写入的原子性：

| 偏移 | 字段 | 类型 | 含义 |
|------|------|------|------|
| `0x00` | `m_crcDigest` | `uint32` | 数据区 CRC32（校验范围为数据文件偏移 4 起、长度 `actualSize`） |
| `0x04` | `m_version` | `uint32` | meta 版本，见下表 |
| `0x08` | `m_sequence` | `uint32` | 全量回写代数；重整后递增，供多进程感知 |
| `0x0C` | `m_vector` | `uint8[16]` | AES-CFB IV（`MMKVVersionRandomIV` 起） |
| `0x1C` | `m_actualSize` | `uint32` | 权威有效载荷长度（`MMKVVersionActualSize` 起） |
| `0x20` | `lastActualSize` | `uint32` | 上次已确认的 actualSize（崩溃恢复） |
| `0x24` | `lastCRCDigest` | `uint32` | 上次已确认的 CRC |
| `0x28` | `_reserved` | `uint32[16]` | 保留 |
| `0x68` | `m_flags` | `uint64` | 特性开关（如 `EnableKeyExpire = 1<<0`） |

**版本号（节选）：**

| 值 | 名称 | 引入内容 |
|----|------|----------|
| 0 | `MMKVVersionDefault` | 初始 |
| 1 | `MMKVVersionSequence` | `m_sequence` |
| 2 | `MMKVVersionRandomIV` | 随机 IV |
| 3 | `MMKVVersionActualSize` | meta 内 `m_actualSize` + confirmed 信息 |
| 4 | `MMKVVersionFlag` | `m_flags` |

本包将 meta 读到 `0x70`（含 `m_flags`）解析为 `MMKVInfo`，挂在 `MMKVReader.Info`（仅当传入 `crc` 时非 nil）。解密路径**实际使用** `IV` 与 `ActualSize`；不校验 CRC，不根据 `Flags` / sequence 改变行为。
