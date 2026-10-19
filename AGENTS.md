# AGENTS.md

给在本仓库工作的 coding agent 的简短指南。人类开发者说明见 [README.md](./README.md)。

## 项目是什么

- **只读** Go 库：解析 Tencent MMKV 数据文件 + 可选 `.crc`。
- 模块：`github.com/unlock-music/go-mmkv`，包名 `go_mmkv`。
- 主要消费场景：unlock-music 等工具从 App 本地 MMKV 抽字符串配置；不是完整 MMKV runtime。

改代码前先读 [docs/FORMAT.md](./docs/FORMAT.md)，避免把 ItemSizeHolder / meta 字段搞错。

## 源码地图

| 文件 | 职责 |
|------|------|
| `mmkv.go` | `MMKVReader`、meta 解析、varint / String / Container、KV 读取 |
| `crypto.go` | AES-128-CFB 解密流（`cipher.NewCFBDecrypter`） |
| `utils.go` | `MMKVToMap` 便捷封装 |
| `mmkv_test.go` | 行为测试；样例在 `testdata/` |

不要新增与「只读解析」无关的写路径、网络、CLI，除非用户明确要求。

## 格式要点（实现时易错）

1. **双文件**：`<id>` 数据 + `<id>.crc` meta。加密库几乎总要 `.crc`（取 IV + 权威 `ActualSize`）。
2. **数据文件**：`uint32 LE actualSize` → **ItemSizeHolder**（约 4 字节 varint，现行为随机伪装值）→ KV 追加记录。`NewMMKVReader` 必须跳过 ItemSizeHolder（当前用一次 `ReadInt()`）。
3. **加密边界**：仅加密偏移 4 之后的载荷；头 4 字节明文。算法 **AES-128-CFB**，key = 调用方传入的 16 字节，IV = meta `m_vector`。
4. **ActualSize 来源**：无 `crc` → 数据文件头；有 `crc` → `meta.ActualSize`（覆盖文件头）。
5. **Meta 布局**：见 [docs/FORMAT.md](./docs/FORMAT.md)。`readMeta` 读 `0x70` 字节到 `MMKVInfo`（含 `LastActualSize` / `LastCRCDigest` / `Flags`@`0x68`），挂到 `MMKVReader.Info`。解密路径只用 IV + `ActualSize`；`Flags` 仅暴露不作行为开关。
6. **字符串 value**：外层 Container + 内层 String；空 container ≈ 删除/空值。
7. **不校验 CRC32**；不要假装已经校验。

## 支持范围（改 API 时对齐）

**做：** 流式读、解密、string map、安全限额读取、跳过 container。

**不做（除非用户点名）：** 写入、CRC 校验、AES-256、完整类型封装、key 过期、多进程锁/sequence 逻辑。

## 约定

- 对外错误信息带 `go-mmkv:` 前缀（与现有风格一致）。
- 保持 `io.Reader` 流式接口；避免一次性 `ReadAll` 除非测试需要。
- `password == nil` → 不解密；`crc == nil` → 不读 meta（明文路径）。
- `maxReadSize < 0` → 不额外截断。
- 测试用 `testify/assert`；改解析逻辑时同步更新或新增 `testdata/` 用例。
- 不要顺手重构无关文件；不要改 `go.mod` 模块路径。

## 验证

```bash
go test ./...
```

加密用例：`testdata/crypto` + `testdata/crypto.crc`，密码 `unlock-music:key`（见 `mmkv_test.go`）。

## 文档分工

| 文件 | 读者 | 内容 |
|------|------|------|
| `README.md` | 开发者 | 用法、支持矩阵、API |
| `docs/FORMAT.md` | 开发者 / Agent | MMKV 盘上格式 |
| `AGENTS.md` | Agent | 导航、约束、易错点 |

改格式说明改 `docs/FORMAT.md`；改支持范围同步 README + AGENTS。
