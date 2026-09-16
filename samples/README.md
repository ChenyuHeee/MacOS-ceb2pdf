# 测试样本

样本文件本身不入库（第三方公文，见 `.gitignore`）。
测试通过 SHA-256 对齐，把对应文件放到 `ceb/` 目录即可。

全部 18 个样本都已实测：容器解析通过，Founder-RC4 层解出 `%PDF-` 头。
下表的 `algo` / `maker` / `页数` 均为实测值，不是推断。

## 清单

| 文件 | 来源 | 体积 | 签名 | 段数 | algo | Maker | 页数 |
|------|------|-----:|------|-----:|------|-------|-----:|
| `gw-2014-526.ceb` | 国网公文（原有样本） | 501674 | `Founder CEB\0` v3 | 6 | `0x80000002` | 3.2 P / 20140527 / XP | 18 |
| `gh-hhtczengjing-ceb2pdf-test-v2.99D.ceb` | `raw.githubusercontent.com/hhtczengjing/ceb2pdf/HEAD/test.ceb`（MIT 仓库测试夹具，内容是 Adobe *PDF Reference*） | 5158838 | `Founder CEB 2.99D` | 4 | `0x00000000` | 无 | 696 |
| `moa-gov-cn-2012-syj-1712gg-v2.50.ceb` | `www.moa.gov.cn/govpublic/SYJ/201202/P020120224593110510374.ceb` | 13499 | `Founder CEB 2.50` | 6 | `0x80000001` | 3.2 P / 20120220 / XP | 3 |
| `moa-gov-cn-2012-syj-v2.50-7sec.ceb` | `www.moa.gov.cn/govpublic/SYJ/201211/P020121130419826163112.ceb` | 16798 | `Founder CEB 2.50` | 7 | `0x80000001` | 3.2 P / 20121130 / XP | 5 |
| `moa-gov-cn-2013-bgt-v2.50-7sec.ceb` | `www.moa.gov.cn/govpublic/BGT/201305/P020130522602467011311.ceb` | 12856 | `Founder CEB 2.50` | 7 | `0x80000001` | 3.2 P / 20130522 / XP | 2 |
| `moa-gov-cn-2017-syj-v2.50-7sec.ceb` | `www.moa.gov.cn/govpublic/SYJ/201707/P020170705578804794099.ceb` | 42301 | `Founder CEB 2.50` | 7 | `0x80000001` | 3.2 P / 20170704 / XP | 16 |
| `moa-gov-cn-2017-syj-feixing-v3-maker5.0.ceb` | `www.moa.gov.cn/govpublic/SYJ/201704/P020170425352230422071.ceb` | 2246033 | `Founder CEB\0` v3 | 6 | `0x80000001` | 5.0 P / 20170421 / Win7 | 10 |
| `moa-gov-cn-2019-tzgg-v2.50-7sec.ceb` | `www.moa.gov.cn/gk/tzgg_1/tz/201901/P020190129421632167788.ceb` | 60895 | `Founder CEB 2.50` | 7 | `0x80000001` | 3.2 P / 20190128 / XP | 24 |
| `zys-moa-gov-cn-2019-v2.50-7sec.ceb` | `www.zys.moa.gov.cn/gzdt/201902/P020190522361402904498.ceb` | 20209 | `Founder CEB 2.50` | 7 | `0x80000001` | 3.2 P / 20190218 / XP | 7 |
| `zzj-moa-gov-cn-2019-v2.50-7sec.ceb` | `www.zzj.moa.gov.cn/gzdt/201902/P020190522361404949446.ceb` | 16302 | `Founder CEB 2.50` | 7 | `0x80000001` | 3.2 P / 20190218 / XP | 5 |
| `zzj-moa-gov-cn-2019-23MB-v3.ceb` | `www.zzj.moa.gov.cn/gsgg/201908/P020190801622431195464.ceb` | 23026507 | `Founder CEB\0` v3 | 6 | `0x80000001` | 5.0 P / 20190801 / Win7 | 153 |
| `hunan-gov-cn-gazette-maker3.0-2005-v2.50.ceb` | `www.hunan.gov.cn/hnszf/szf/hnzb_18/zb0713/202106/19794023/files/27e05e71a8d34a55b023def3c90fac53.ceb` | 6889162 | `Founder CEB 2.50` | 6 | `0x80000001` | 3.0 P / 20050530 / XP | 40 |
| `hunan-gov-cn-gazette-maker3.0-2005b-v2.50.ceb` | `www.hunan.gov.cn/szf/hnzb_18/zb0713/202106/19793275/files/3a59e087b728489bbb96c8adb05f463d.ceb` | 4933491 | `Founder CEB 2.50` | 6 | `0x80000001` | 3.0 P / 20050205 / XP | 40 |
| `hunan-gov-cn-gazette-5sec-algotype0-v2.50.ceb` | `www.hunan.gov.cn/hnszf/szf/hnzb_18/zb0713/202106/19670751/files/e63e44e8fd5f4e3282c77fe817c3ded9.ceb` | 4718187 | `Founder CEB 2.50` | 5 | `0x80000002` | 无 | 40 |
| `zj-gov-cn-2012-5sec-no-type16-v2.50.ceb` | `www.zj.gov.cn/api-gateway/jpaas-web-server/front/document/file-download?fileUrl=/cms_files/jcms1/web3096/site/attach/0/2cb61b8fe9a04e9a888fdf09a56ce54b.ceb` | 93430 | `Founder CEB 2.50` | 5 | `0x80000002` | 无 | 18 |
| `wuhan-gov-cn-2020-5sec-no-type16-v2.50.ceb` | `www.wuhan.gov.cn/zwgk/xxgk/zfwj/bgtwj/202003/P020200721578077337477.ceb` | 298512 | `Founder CEB 2.50` | 5 | `0x80000002` | 无 | 7 |
| `hunan-gov-cn-gazette-26MB-5sec-algotype0-v2.50.ceb` | `www.hunan.gov.cn/szf/hnzb_18/zb0713/202106/19728892/files/1c56ff90eecc4ba791b9a5bdd4a71a20.ceb` | 26336077 | `Founder CEB 2.50` | 5 | `0x80000001` | 无 | 240 |
| `zcggs-moa-gov-cn-2018-v3-maker5.0.ceb` | `www.zcggs.moa.gov.cn/ncjtzcjdgl/201904/P020190423592745804211.ceb` | 3101953 | `Founder CEB\0` v3 | 6 | `0x80000001` | 5.0 P / 20180126 / Win7 | 28 |

## SHA-256

```
e913c6b13609c81215ed59a982f457f575ce42edcd7065dae558d5ec58ce63f7  gw-2014-526.ceb
ab1071e9317fcae1528d0b491478a885fa178e46b484bcf55a935d67e65467ad  gh-hhtczengjing-ceb2pdf-test-v2.99D.ceb
06a1a4a61efc8b7a4ad1f5ad729cf71ec5f0a6dc311065814a1f55952814720f  moa-gov-cn-2012-syj-1712gg-v2.50.ceb
bd169b71e4f8365f95cb394a22390e0cdf275a774a62af380343d2a8d95698f3  moa-gov-cn-2012-syj-v2.50-7sec.ceb
935713e1f99a6c4ce1ab907f7945c46b08e9927c068d28f9fe641246f2597349  moa-gov-cn-2013-bgt-v2.50-7sec.ceb
fd6717abd1897b7360a9dad3f2c500c371766b375866e22c55e9030fe8903822  moa-gov-cn-2017-syj-v2.50-7sec.ceb
ab675db147d0ac7e55f386d0ff423e466d00b1d3149bb8a4c38b58dc2d0c9da4  moa-gov-cn-2017-syj-feixing-v3-maker5.0.ceb
f7ec892c2c23cdccf235ac844a80f341be3d951c2a05c280a50dae776d7f7873  moa-gov-cn-2019-tzgg-v2.50-7sec.ceb
84fb04cda2111e59a5ceda68702de86ab88c56ee9e23480db26da754cd2902cc  zys-moa-gov-cn-2019-v2.50-7sec.ceb
cb027916c9eff3959ff917298279b7f68e91622e0faf52a8bd066bacd1ea7b31  zzj-moa-gov-cn-2019-v2.50-7sec.ceb
3bf63f39a3638f5850283a330d27cc03689d4748cfb6d86110a41831fb7c44e7  zzj-moa-gov-cn-2019-23MB-v3.ceb
8d9ccc17d6597438b107c027a7d54161b61b57ab66a68fb54cb2d3a7bdb996ab  hunan-gov-cn-gazette-maker3.0-2005-v2.50.ceb
c5c31e6f5e8bd332bcb02c8d20d39ff8f250b7d57132cf853a270ede9804371d  hunan-gov-cn-gazette-maker3.0-2005b-v2.50.ceb
98931f37b8630e33a5575fd2d5773a56703d0b5384dcb8ebfd6d2315b2e03d76  hunan-gov-cn-gazette-5sec-algotype0-v2.50.ceb
3d42943af42a95a6ba1aae6961bf20e978f48c0f83e1bc1eb7924a90f40263e0  zj-gov-cn-2012-5sec-no-type16-v2.50.ceb
fc631e51515a2eced4119e774fd746dd335b745d0dd83a03f7012e0d70a378f7  wuhan-gov-cn-2020-5sec-no-type16-v2.50.ceb
ba944850842488a2c9c88ca9d523cda5d694c317ccc7a4550f4ae77960cd9ac6  hunan-gov-cn-gazette-26MB-5sec-algotype0-v2.50.ceb
b6e4b3c9e486b6595a36aa3deed6b64cd0d7344afc155fbba9e2382f40554b1d  zcggs-moa-gov-cn-2018-v3-maker5.0.ceb
```

## 这批样本推翻的假设

原来只有一个样本时成立、多样本下全部不成立的那些：

1. **魔数不是 `"Founder CEB\0"`。** 还有 `"Founder CEB 2.50"`、`"Founder CEB 2.99D"`
   ——第 12 字节（0x0B）是**空格**不是 NUL。安全的判据是前 11 字节 `Founder CEB`。
   18 个样本里 14 个过不了 12 字节判据。
2. **0x0E 的 u16 只在 v3 里是版本号。** 2.50/2.99 把 0x0C–0x0F 当 ASCII 版本串用，
   读出来是 12341（`"99"`）、14649 之类的垃圾。
3. **PDF 主体段不固定是 type 3。** 18 个里有 16 个主体是 **type 2**，
   同时还存在一个 **长度为 0 的 type 3 诱饵段**——按 type 3 取会拿到空缓冲区。
4. **算法 ID 段不固定是 type 16。** 见过 type 16、type 0、type 34。
5. **段表会和第一段数据重叠。** 多数样本满足 `第一段偏移 == 0x16 + u32@0x10`，
   于是最后一个表项的 type 字节和 8 字节"保留"字段**就是主体的前几个字节**。
   `type=183`、`type=34`+`rsv=d183…` 都是这么来的假值。最后一项的 type 不可信。
6. **段表不保证按偏移递增。** zj / wuhan 样本里那个零长 type 3 的偏移指向 EOF。
7. **Maker 段的 type 码不稳定**：255、0、7 都见过（还有被重叠覆盖的）。

稳妥的做法是**按形状认段**，不要按 type 码：主体 = 最长的段，
RC4 密钥 = 16 字节段，对称密钥 = 64 或 24 字节段，算法 ID = 4 字节段，
制作信息 = 150 字节段。这套规则在全部 18 个样本上成立。

## 算法 ID 低位确实选模式

在 algo=1 和 algo=2 的样本上逐流实测 zlib 可解性：

| 样本 | algo | OFB | CFB64 | CFB8 | 不解密 |
|------|------|----:|------:|-----:|-------:|
| `moa-gov-cn-2013-bgt` | `0x80000001` | **2/2** | 0/2 | 0/2 | 0/2 |
| `moa-gov-cn-2012-syj-1712gg` | `0x80000001` | **4/5** | 0/5 | 0/5 | 0/5 |
| `zj-gov-cn-2012` | `0x80000002` | 0/20 | **19/20** | 0/20 | 0/20 |

和参考实现的 enum 完全对上：`1 = TYPE_3DES_OFB`、`2 = TYPE_3DES_CFB`。
（差的那 1 个是朴素 `stream` 关键字扫描的误匹配，不是解密失败。）

`0x00000000`（gh 2.99D 样本）= **没有第二层**：只做 RC4，主体里连 `/Encrypt`
都没有，775 个流里 767 个直接 inflate 成功。

## 还缺的维度

- **带真实授权绑定的样本**（图书馆借阅本）。没找到公开可自由下载的。
  所有 18 个样本的密钥都完整存在文件自身内，没有一个需要授权服务器。
- **IDEA / RC5 / CAST256 的算法 ID**（enum 里的 4–15）。野外只见过 0、1、2。
