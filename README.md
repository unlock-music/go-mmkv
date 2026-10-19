# go-mmkv

Go 实现的 [Tencent MMKV](https://github.com/Tencent/MMKV) **只读解析器**。用于从 MMKV 数据文件（及可选的 `.crc` 元数据文件）中流式读取 key-value，支持 AES-128-CFB 加密库。

模块路径：`github.com/unlock-music/go-mmkv`

## 安装

```bash
go get github.com/unlock-music/go-mmkv
```

## 快速上手

### 明文库 → `map[string]string`

```go
f, err := os.Open("mmkv.default")
if err != nil {
    log.Fatal(err)
}
defer f.Close()

m, err := go_mmkv.MMKVToMap(f, nil, nil)
if err != nil {
    log.Fatal(err)
}
fmt.Println(m["world"]) // "hello"
```

### 加密库（需要 `.crc` + 密码）

```go
mmkv, _ := os.Open("crypto")
crc, _ := os.Open("crypto.crc")
defer mmkv.Close()
defer crc.Close()

// password 为 16 字节 AES-128 密钥；IV 从 .crc 读取
r, err := go_mmkv.NewMMKVReader(mmkv, -1, []byte("0123456789abcdef"), crc)
if err != nil {
    log.Fatal(err)
}
for !r.IsEOF() {
    key, err := r.ReadKey()
    if err != nil {
        log.Fatal(err)
    }
    val, err := r.ReadStringValue()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("%s = %s\n", key, val)
}
```

`maxReadSize < 0` 表示不额外截断，按文件/`ActualSize` 读到有效数据末尾。

## 本包支持什么

| 能力 | 状态 |
|------|------|
| 流式读取明文 MMKV 数据文件 | ✅ |
| 读取 `.crc` 元数据（IV、`ActualSize` 等） | ✅ |
| AES-128-CFB 解密（密钥 16 字节，IV 来自 `.crc`） | ✅ |
| Protobuf 风格 varint / String / Container | ✅ |
| 便捷 `MMKVToMap`（string → string） | ✅ |
| 带上限的安全读取（`ReadIntSafe` / `ReadStringSafe`） | ✅ |
| 跳过未知 value（`SkipContainer`） | ✅ |
| 写入 / 原地修改 MMKV | ❌ |
| CRC32 校验 | ❌ |
| AES-256-CFB | ❌ |
| 完整类型 API（bool / float / bytes 等专用解码） | ❌（可用底层 `ReadInt` / `ReadBytes` 自行解析） |
| Key 过期、多进程 sequence 语义 | ❌ |

设计目标是**取证 / 解锁 / 数据分析场景下的只读解析**，不是 MMKV 的完整兼容实现。

## MMKV 文件格式

见 [docs/FORMAT.md](./docs/FORMAT.md)。

## API 概览

- `NewMMKVReader(source, maxReadSize, password, crc)` — 构造读取器；`crc == nil` 时按数据文件头的 `actualSize`；提供 `crc` 时以 meta 为准并填充 `Info`，加密时还需 `password`。
- `MMKVReader.Info` — 解析后的 `.crc` meta（无 `crc` 时为 nil）。
- `(*MMKVReader) ReadKey` / `ReadStringValue` — 读下一对字符串 KV。
- `(*MMKVReader) ReadInt` / `ReadBytes` / `SkipContainer` — 底层原语。
- `(*MMKVReader) IsEOF` / `BytesAvailable` — 边界。
- `MMKVToMap` — 一次性读成 `map[string]string`。

## 测试

```bash
go test ./...
```

样例数据在 `testdata/`（明文、字符串 overlap、整型、加密 + `.crc`）。

## 许可

以仓库内声明为准。MMKV 格式版权归 Tencent MMKV 项目（BSD-3-Clause）。
