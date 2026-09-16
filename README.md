> **For coding agents:** install with `cargo install --git https://github.com/ChenyuHeee/MacOS-ceb2pdf --locked`, then run `ceb2pdf FILE.ceb` to write `FILE.pdf` beside it — every positional argument is an input (use `-o` for the output), and exit code 3 means "converted, but read the warnings".

# ceb2pdf

把方正 Apabi 的 `.ceb` 文档转成 PDF。**无损、轻量、无需 Wine**。

## 为什么是无损的

CEB 不是一种独立的版式格式 —— 它是一个被两层弱加密包裹的**标准 PDF**：

```
Founder CEB 容器
└── 主体段 ──> Founder-RC4（整体，每 64 KiB 重置状态）
                └── 标准 PDF
                    └── 各 stream ──> 3DES（模式由容器里的算法 ID 指定）
```

所以转换不需要渲染引擎、不处理字体、不做 OCR。解开两层加密、抹掉 `/Encrypt`
标记，得到的**就是原始 PDF 本身** —— 矢量文字、书签、图像原样保留。

因为流密码长度不变，整个过程是**原地**完成的，PDF 的 xref 偏移全部保持有效。

格式细节见 [FINDINGS.md](FINDINGS.md)。

## 安装

```sh
cargo install --git https://github.com/ChenyuHeee/MacOS-ceb2pdf --locked
```

或者从源码构建：

```sh
git clone https://github.com/ChenyuHeee/MacOS-ceb2pdf
cd MacOS-ceb2pdf && cargo build --release
# 产物在 target/release/ceb2pdf
```

需要 Rust 1.85+。主要面向 macOS（Apple Silicon 与 Intel），Linux 同样可用（CI 有覆盖）。

## 用法

```sh
ceb2pdf 文件.ceb                      # 输出 文件.pdf（就放在旁边）
ceb2pdf 文件.ceb -o 别的名字.pdf       # 指定输出
ceb2pdf *.ceb -o 输出目录/             # 批量，自动并行
ceb2pdf 文件.ceb -v                   # 逐层报告做了什么
ceb2pdf --dump-meta 文件.ceb          # 只看容器结构，不转换、不写文件
```

转换一个文件的样子：

```
$ ceb2pdf 农办办2013-20号.ceb
农办办2013-20号.ceb -> 农办办2013-20号.pdf
  12,856 -> 10,685 B PDF, 2 streams, 2/2 content streams inflate
```

### 选项

| 选项 | 说明 |
|---|---|
| `-o, --output <路径>` | 单个输入时是输出文件；多个输入时必须是**已存在的目录** |
| `-j, --jobs <N>` | 并行线程数，默认 `min(CPU 数, 文件数)` |
| `-f, --force` | 覆盖已存在的输出文件 |
| `-v, --verbose` | 逐层报告；重复 `-vv` 看每个段的细节 |
| `-q, --quiet` | 只输出错误与警告 |
| `--dump-meta` | 打印容器结构后退出，不转换也不写任何文件 |
| `--no-verify` | 跳过转换后的自检 |
| `--force-mode <模式>` | 覆盖容器声明的算法 ID（`none` / `ofb` / `cfb64`），仅用于诊断异常文件 |

### 退出码

| 码 | 含义 |
|---|---|
| `0` | 转换成功，自检干净 |
| `1` | 失败 |
| `3` | 转换完成，但自检发现问题 —— **请阅读警告**，输出可能不完整 |

### 关于覆盖文件

**所有位置参数都是输入，没有位置输出参数。** 所以 `ceb2pdf *.ceb out.pdf` 不会
把 `out.pdf` 当成输出而吃掉一个样本 —— 它会被当作第四个输入。写到输入文件上
一律拒绝，覆盖已有输出需要 `-f`。

## 出问题时

先看 `--dump-meta`，它会解释这个文件的结构以及解析器是怎么判断的：

```
$ ceb2pdf --dump-meta 文件.ceb
  version      : 2.50w
  sections     : 7
    type   2 unrecognised     offset       141  len     10685
    type   3 PDF body         offset     10826  len         0
    ...
  resolved     : body=10685 B, rc4_key=16 B, key_blob=64 B, algorithm=0x80000001
  note         : PDF body: the longest section has type byte 2, not 3; identified by size
```

对于不认识的算法 ID、不认识的容器版本、授权绑定的文件，工具会**明确报错而不是
猜测**。遇到报错请连同 `--dump-meta` 的输出一起反馈。

## 验证状况

在 **18 个真实样本**上端到端验证：全部转换成功，所有 `/FlateDecode` 流解压通过，
输出与 Python 参考实现 [`tools/ceb_poc.py`](tools/ceb_poc.py) **逐字节一致**。

样本覆盖 5 种容器版本（空 / `2.50f` / `2.50w` / `2.50U` / `2.99D`）、
3 种加密模式（3DES-OFB 13 个、3DES-CFB64 4 个、不加密 1 个）、
制作工具 Maker 3.0 / 3.2 / 5.0、文档年份 2005–2020。

universal binary 763 KB，仅链接 `libz` 与 `libSystem`，唯一第三方 crate 是 `des`。

## 已知限制

- **部分 CEB 不内嵌字体**（18 个样本中有 5 个），只按名引用方正字库，也没有
  `ToUnicode`。在未安装方正字库的机器上会发生字体替换 —— 最明显的症状是方正
  「数码字体」：`〔2013〕20号` 会显示成 `〔圆园员猿〕圆园号`，因为数字字形挂在
  那几个汉字的编码上。
  **这不是转换损失**：CEB 容器里本来就没有这些字体，Apabi Reader 显示正确是
  因为它自带字库。`-v` 会提示哪些文件属于这种情况。
- 流边界采用与上游一致的关键字扫描。全部样本的 `/Length` 交叉校验均无偏差，
  但它终究是关键字扫描，而非完整的 PDF 词法分析。
- **未验证**：带授权绑定（图书馆借阅本之类）的文件。找不到可自由下载的样本，
  工具遇到这类文件的行为目前是未知的。

## 范围

仅处理密钥完整存放在文件自身内的 CEB —— 无授权服务器、无用户凭证绑定。
这属于格式层面的混淆，目的是互操作性：让公开发布的公文能在任何 PDF 阅读器里打开。

带真实授权绑定的文件不在支持范围内。

## 许可证

[MIT](LICENSE)
