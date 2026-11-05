# Assert 与 Disprove 链上成本压缩调研

日期：2026-09-30  
对象：`garbled-stark-verifier` 的 2^18-row 实例，验证器输入为 1,041,024 bit，即 130,128 byte  
结论状态：方法调研完成；三个最有价值的当前共识实验已在远端 Bitcoin Core 31.1 严格标准策略下重放；完整争议交易图仍未实现

## 摘要

当前瓶颈不是 Taproot control block、交易壳或普通授权签名，而是把 1,041,024 bit 与唯一一组 garbled-circuit input labels 绑定。现有 8-bit Schnorr-adaptor Assert 的 funding 加 reveal 为 2,228,054 vB，其中 reveal 的 95.16% 是逐 digit 的 Schnorr signatures。因而，只改 output 数、control tree 或 covenant 只能得到不到 1% 的收益；必须改变每个认证单元携带的 bit 数，或者更换输入认证/争议架构。

本次得到三个可复核的新结果：

1. **保留当前 garbled-circuit 架构时，wider adaptor digit 是风险最低的近期方向。** 16-bit 版本已由真实 BIP340 signatures 完整序列化，并在远端 Core 31.1 strict policy 下接受：funding 2,960 vB，12 笔 reveal 共 1,111,128 vB，总计 **1,114,088 vB / 13 笔交易**，比 8-bit 基线减少 50.00%。但朴素选择表达到 **277.162 GB/keyset**，而且“一个 digit secret 如何只释放相应的多条 binary labels”尚未实现，所以这不是完整协议。10/11-bit 更适合作为实现折中。
2. **若允许替换输入认证和争议架构，ESSPI-style P2TR envelope 将已签名数据运输降至 33,004 vB。** 远端 Core 接受了一笔 154-vB commit 和一笔 32,850-vB reveal，合计 **2 笔交易、1 个确认块**，相对 8-bit adaptor funding+reveal 少 98.52%。但这只是 authenticated transport；ESSPI 的 DA-DAG、secondary BitVMX、fraud paths、bonds、timeouts 与 settlement 都未计入，而且 raw proof bytes 不能直接替代当前 GC 的 selected labels。
3. **Disprove 已经很小。** 对本项目真实的 16-byte output label，把 false-label hashlock 改成由 false label 派生 internal key 的 pointlock，在同样包含 timeout sibling 的公平比较中，从 386 WU / 97 vB 降至 **332 WU / 83 vB**，每次只省 14 vB。它值得作为末端微优化，但不应抢占 Assert 优化资源。

软分叉方向中，CTV/TXHASH/CSFS 只优化 control plane，不能消除 adaptor completions。最有结构性价值的是 **MATT / CCV + vector commitment**：Assert 只提交 execution-trace root，通过交互式 k-section 定位错误 step，再做一个局部 Disprove。其公开估算比当前 GC Assert 小两个数量级，但会引入顺序交互、数据可用性和在线 challenger 假设。Native STARK verification 理论上最小，却是共识面最大、成熟度最低的路线。

## 1. 研究问题与口径

本报告回答五个问题：

1. 在 Bitcoin 当前共识和标准 relay policy 下，保留现有 GC 架构最多能把 Assert 压到什么程度？
2. 若允许更换 input-authentication/争议架构，是否能把 MvB 降至几十 kvB？
3. Disprove 是否值得继续重点压缩？
4. 哪些软分叉真正减少 payload，哪些只减少预签名或交易图复杂度？
5. 现阶段哪些数字是完整 on-chain cost，哪些只是组件成本？

这里的 **on-chain cost** 包括所有被序列化进交易的字段：普通交易签名、认证 witness、tapscript、control block、input/output shell、funding/commit、必要的 join、anchors、timeouts、fee-management 和 settlement。只要缺少其中任何协议必需节点，就必须标作“组件成本”，不能称为完整协议成本。

本报告分开讨论三种指标：

- **正常路径成本**：无人 challenge 时发生的交易。
- **被挑战路径成本**：一次合法 challenge 所需的完整路径。
- **最坏路径成本**：恶意方触发全部可用 dispute/timeout 分支时的总成本和顺序轮数。

当前仓库只精确覆盖若干 funding/reveal/join/Disprove 组件，尚没有完整的 Challenge → Assert → completion → Disprove/Take2 → settlement 图。因此本文不给出虚假的“完整协议总数”。

## 2. 方法与证据等级

文献检索只把论文、作者实现/说明、Bitcoin BIP、Bitcoin Core 源码和 reference implementation 当作定量依据。搜索中特别检查了四类互相竞争的解释：更紧凑的 GC label 认证、普通签名数据运输、交互式 trace commitment、直接在 Script/consensus 中验证 proof。

每个结论使用以下证据等级：

| 等级 | 含义 |
|---|---|
| **E1 Core-tested** | 构造真实签名和完整交易，在远端 isolated regtest 上以 Bitcoin Core 31.1、`acceptnonstdtxn=0` 通过 `testmempoolaccept`、`sendrawtransaction` mempool admission 和本地 mining |
| **E2 serialized** | 由仓库代码精确序列化并断言 weight/vsize；未完成对应的完整协议或未逐个在 Core 重放 |
| **E3 source-reported** | 数字由原论文、BIP 作者或 reference implementation 报告，未在本项目复现 |
| **E4 projection/concept** | 从 E1–E3 公式外推，或仍缺实现/安全证明的设计方向 |

所有项目代码测试都在 `ant-5090-2:/mnt_zkm/stephen/bitcoin-stark-verifier` 运行；本机没有执行测试。E1 harness 创建的是隔离 regtest wallet 和临时 bech32m 地址，先挖 101 个 regtest blocks，再让 wallet 构造 funding/commit；没有使用主网钱包、外部地址或真实资金。

## 3. 已验证基线与成本解剖

### 3.1 当前组件成本

| 认证方式 | funding | reveal | 已测 join | 已测合计 | 交易数边界 | 证据 |
|---|---:|---:|---:|---:|---:|---|
| 8-bit Schnorr adaptor | 5,841 vB | 2,222,213 vB | 未实现 | **2,228,054 vB** | 1 + 23 = **24** | E1 |
| ACW `(2,16)` | 33,836 vB | 11,848,875 vB | 未实现 | **11,882,711 vB** | 1 + 131 = **132** | E1 |
| signed Lamport | 45,016 vB | 17,265,635 vB | 13,060 vB | **17,323,711 vB** | 1 + 174 + 1 = **176** | E1 |

这张表包含相应组件中的 signatures、scripts、controls 和 tx shells，但不包含完整 dispute graph。8-bit adaptor reveal 分三块确认，ACW 分十二块，Lamport reveal 分十八块；这些是 isolated-regtest 容量结果，不是公网上的 propagation/fee 保证。

### 3.2 为什么微调交易壳没有意义

8-bit adaptor 的 8,888,837 WU reveal 中：

- 8,458,320 WU，即 **95.16%**，是 130,128 个 completed-Schnorr signature witness items（每项含 64-byte signature 和 1-byte item-length framing）；
- 394,507 WU，即 **4.44%**，是完整 tapscripts；
- control、其余 framing、inputs/outputs shell 合计只有 36,010 WU，即 **0.41%**。

ACW 和 Lamport 的分布正好说明同一个结论。ACW 有 75.29% 在 script、24.16% 在 openings；Lamport 有 73.91% 在 script、25.63% 在 preimages。二者超过 99% 都是认证原语本身。增加 covenant、减少一个 output 或压缩 control block 不会改变数量级。

因此，优化问题必须写成：

> 如何用更少的链上认证材料，唯一地让 evaluator 获得与已承诺输入对应的 labels，同时不能获得相反 labels，并且任何 observer 都能恢复或 challenge？

只发布 raw bits、只承诺一个 hash，或者只让普通签名“认证交易”，都没有自动解决这个 label-selection 问题。

## 4. 当前共识下保留 GC 的方法

### 4.1 Wider Schnorr-adaptor digits

BitVM3 的 adaptor 构造让每个 digit 的某一个 completion 同时完成交易签名和选择认证。作者说明明确讨论了 8-bit 和 11-bit digits；Glock 也说明更大的 alphabet 可以降低 on-chain 数量，但 setup 必须为每个可能值准备一项。这里将同一序列化形状扩展到 10/11/12/16 bit。

令 `k` 为每枚 completion 表示的 bit 数，`D = ceil(1,041,024/k)` 为 digit 数，`I` 为 inputs，`T` 为 reveal transactions。对本 fixture 中每个 `n >= 253` digits 的 input，完整两输出交易满足：

```text
serialized bytes = 98 + 112 I + 68 D
weight            = 386 + 235 I + 68 D
vsize              = ceil(weight_per_tx / 4) 后逐笔求和
```

标准交易上限为 400,000 WU；当前形状每笔最多 5,855 digits。对应结果为：

| bits/digit | digits | inputs | reveal tx | reveal vB | funding vB | funding+reveal | 总交易 | 相对 8-bit | 朴素表/keyset |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 130,128 | 133 | 23 | 2,222,213 | 5,841 | **2,228,054** | 24 | baseline | 2.165 GB |
| 10 | 104,103 | 107 | 18 | 1,777,775 | 4,723 | **1,782,498** | 19 | -20.00% | 6.929 GB |
| 11 | 94,639 | 97 | 17 | 1,616,206 | 4,293 | **1,620,499** | 18 | -27.27% | 12.598 GB |
| 12 | 86,752 | 89 | 15 | 1,481,461 | 3,949 | **1,485,410** | 16 | -33.33% | 23.097 GB |
| 16 | 65,064 | 66 | 12 | 1,111,128 | 2,960 | **1,114,088** | 13 | -50.00% | 277.162 GB |

表大小按 `65 × 2^k × D` byte 计算，只计每个可能值的一项 65-byte adaptor record，不计 points、索引、元数据和多份 keysets；它是便于比较的保守主项，不是完整 setup 文件大小。末尾不足 `k` bit 的 digit 若专门裁剪选择空间，可略减表大小。

**验证状态。** 所有五种 width 的交易 packing 和精确序列化是 E2。16-bit 版本进一步生成了全部真实 completed BIP340 signatures，并完成 E1 Core replay：funding 含 66 个协议 P2TR outputs 和一个 wallet-change output，共 2,960 vB；12 笔 reveal 为 1,111,128 vB；最大 reveal 为 399,936 WU。未确认 funding 加一笔 99,984-vB full reveal 因 101-kvB cluster limit 被拒，因此整组 reveals 不能与未确认 funding 同时进入同一 standard-policy cluster；先确认 funding 后全部 accepted，reveals 再用两个 blocks 挖完。原始报告在 `data/run-adaptor16-core31-regtest.json`。

**未解决的安全条件。** 当前 verifier 是 Boolean Yao circuit。一个 16-bit digit completion 只说明“选择了 0..65535 中一个值”，并不会自动产生 16 条正确 binary input labels。安全实现必须满足以下二者之一：

1. 将相关输入真的改造成 `2^k`-ary wires，并证明 garbling 的 privacy/authenticity；或
2. 由一个 digit secret 通过经过证明的 KDF/encryption bundle 只释放该 digit 对应的 `k` 条 binary labels，且不能组合出相反 labels。

当前 fixture 只构造实际选择到的 completions，没有构造完整的 `2^k` table、GC selector mapping、Mosaic correlation 或安全证明。因此，16-bit 的 E1 只证明“交易形状通过 Core 31.1 strict-standard-policy mempool admission 并可由本地 regtest miner 打包”，不是“16-bit GC 协议已经完成”。

**判断。** 16-bit 是链上空间上界实验，不适合直接部署。10-bit 表仅比 8-bit 大 3.2 倍而省 20%；11-bit 有作者设计先例，省 27.27%，但表放大约 5.82 倍。下一步应实现并 Core-test 10/11-bit 的真实 choice table 与 label-delivery，之后再决定是否承受 12-bit 的 23.1-GB/keyset 表。

### 4.2 WOTS translation 与 Antichain Winternitz

WOTS-to-Lamport translation 用离线 secret-sharing table 把单调 WOTS openings 转成互斥 Lamport labels。论文报告相对 Lamport 超过 3 倍的 script 缩减，本项目依据论文的 508-bit Assert 得到约 7.38 vB/bit 的边际率。它在 hash-only 假设下保留 GC label 选择语义，但 translation tables 随 chunk weight 二次增长。

Antichain Winternitz 通过 constant-sum antichain 保证任何被 Script 接受的 opening 都映射到一个合法 codeword，并支持 permissionless recovery。本项目的安全、带普通交易签名的 ACW `(2,16)` fixture 已经 E1 验证，但 funding+reveal 为 11.88 MvB，明显大于 adaptor 的 2.23 MvB。它的价值是 hash-based、恢复语义清晰，而不是当前最小链上成本。

两者与 wider adaptor 的取舍是：WOTS/ACW 把主要成本放在 hashes、openings 和 scripts，保留 hash 假设；adaptor 把主要成本放在 Schnorr completions，链上更小但依赖 discrete log，且扩大 digit 会导致指数选择表。

### 4.3 Mosaic 解决的是多副本，不是单副本

Mosaic 用 polynomial label correlation，使 cut-and-choose 留下的多个 GC copies 能由一个链上 missing share 恢复，因此 on-chain footprint 不随 retained-copy 数线性增长。它正好针对本项目 `M = 7` 时“是否要发布七套 labels”的问题。

但 Mosaic 不会把一套 8-bit adaptor 的 2.23 MvB 自动压成几十 kvB；它避免的是错误的 `7×` 放大。当前仓库只把 one-keyset 成本列成 headline，并把 `M=7` 明确标作 projection，所以要在完整协议中得到这项收益，仍需实现 polynomial correlation、setup verification 与本项目 hash-based garbling的 soldering。

### 4.4 TinyLabels 和 PIPEs 为什么不能直接采用

TinyLabels 的在线 input-label communication 接近 `1 + o(1)` bit/label，说明“百万 labels 必须百万倍 16-byte”并不是信息论下界。但是其目标是两方 GC communication，依赖 Ring-LWE 和 offline material；它没有提供 Bitcoin Script 可执行的 public recovery、penalty 和 permissionless fraud proof。因此不能把其在线 communication 数字直接记作链上 Assert。

PIPEs v2 在抽象上更激进：Assert 只放一个 hash，Disprove 只需一个 signature，因为 witness encryption 最终释放一个 Schnorr signing key。问题是文中 AADP 实例对小型 SNARK verifier 已估算约 338 TB ciphertext，依赖启发式/extractable-WE 假设，而且 BitVM mapping 要求 setup 时知道 witness/hash。它在语义上最接近“一 hash Assert、一 sig Disprove”，在工程上却远离当前可用范围。

## 5. 当前共识下替换输入架构

### 5.1 ESSPI-style signed P2TR envelope

ESSPI 的核心不是让 Script 直接验证任意消息上的 Schnorr signature，而是让 Bitcoin transaction signature 间接认证 envelope 中的数据，再由第二个 BitVMX instance 验证 signature/hash/OTS-digest 的一致性，并用 DA-DAG 处理 commit/reveal、缺失数据和 equivocation。相比逐 bit OTS，它接近 1:1 data expansion。

本项目构造了一个精确 transport fixture：

- payload：130,128 byte；
- tapscript：130,917 byte，由 250 个 520-byte pushes、一个 128-byte push、publisher key/checksig 和 skipped branch framing 组成；
- reveal base size：94 byte；
- witness 包含 64-byte `SIGHASH_DEFAULT` signature、完整 tapscript 和 33-byte control block；
- reveal：131,118 serialized byte、131,400 WU、**32,850 vB**；
- wallet-signed commit：**154 vB**；
- commit + reveal：**33,004 vB / 2 tx / 1 confirmation block**。

这两个交易均为 E1：Core 31.1 strict policy 在 commit 未确认时也接受 parent+child，并在一个 block 内确认。相对 8-bit adaptor funding+reveal 的 2,228,054 vB，transport 缩减 **2,195,050 vB，即 98.52%，约 67.5 倍**。原始报告在 `data/run-esspi-envelope-core31-regtest.json`。

这个结果包含 commit/reveal 的普通签名、envelope script、control block 和 tx shell，所以不是“只数 payload”的 32.5-kvB 下界。但它仍然**不是完整 ESSPI cost**，没有包含：

- kickoff、penalty、continuation 和 malformed/missing commit/reveal 分支；
- secondary BitVMX instance 及其 input/hash/signature disagreement search；
- bonds、relative timelocks、connectors、anchors、fee bump 和 settlement；
- 从两方 ESSPI 扩展到 permissionless/multiparty BitVM3 的机制。

ESSPI 论文没有给出这些对象的完整 serialized total，且明确把完整 formal model 留作范围外。因此 33,004 vB 只能称为 **authenticated data transport component**。

更关键的是，当前 GC evaluator 需要每个 input wire 的唯一 selected label，而 envelope 发布的是 raw proof bytes。若直接公开两套 labels，challenger 能对有效 proof 构造错误 evaluation；若只公开 raw bits，challenger又无法执行现有 garbled verifier。因而 ESSPI 有两种正确定位：

1. **架构分支**：改用 ESSPI + BitVMX 验证 proof/输入，不再沿用当前 GC input-label Assert；
2. **待研究组合**：保留 GC，但另造可挑战的 selector/label-delivery layer，把 envelope commitment 与唯一 labels 绑定。

在第二项解决之前，不能把 33,004 vB 写进论文作为“优化后的 GC Assert”。

### 5.2 纠正：未经验证的普通 witness 不是安全 Assert

早期 `unverified_reveal_and_response_on_demand` 原型把 998 个 520-byte values 放进初始 witness，再由一个 drop-only script 接受。这只能做容量算术，不能做标准、安全的协议：

1. Core 31.1 对 Tapscript 初始 witness item 的标准策略上限是 80 byte，因此 520-byte arguments 非标准；
2. drop-only leaf 没有交易授权，任何人都能重定向 outputs；
3. 即使加 `CHECKSIG`，BIP341 signature 也不承诺普通 witness arguments。第三方可保留同一 txid、改变 wtxid 和 payload，而原签名仍有效；
4. 后续 child Script 无法读取父交易 witness，因而 challenge response 没有绑定到首次 Assert 的同一 chunk；
5. annex 虽进入 sighash，却被 Core standard policy 拒绝，而且 child 仍不能 introspect 父 annex。

所以“不同 response 只伤害 operator”的旧推理不成立：首次 payload 可以是任意垃圾，response 再换成另一份有效 opening。ESSPI envelope 之所以成立，是数据被放进 revealed tapscript，先由 TapLeaf/P2TR output commitment 绑定，再由 transaction signature 认证；但完整 DA-DAG 仍然不可省略。

## 6. Disprove 的可行微优化

### 6.1 False-label-derived Taproot pointlock

Glock 已使用 `O0 = o0 G`：获得 false-output secret 后可直接产生普通 Schnorr signature，避免最终 Lamport verification。本项目把同一思想用于 Disprove connector：

```text
s = hash_to_scalar("garbled-stark-verifier/disprove-pointlock/v1" || false_label)
P = sG
Q = P + TapTweak(P || timeout_root)G
```

challenger 获得 `false_label` 后可重建 tweaked secret，通过 Taproot key path 花费；operator 的延时路径保留在一个 timeout leaf 中。

精确结果：

| Disprove 形状 | weight | vsize | 说明 |
|---|---:|---:|---|
| BitVM3 的 32-byte depth-0 hashlock | 370 WU | 93 vB | 来源口径，不是本项目 16-byte label |
| 本项目 16-byte depth-0 hashlock | 354 WU | 89 vB | E2；不含 timeout sibling |
| 本项目 16-byte hashlock + timeout sibling | 386 WU | 97 vB | 65-byte control block，公平基线 |
| pointlock key path + timeout sibling | **332 WU** | **83 vB** | 一枚真实 64-byte BIP340 signature |

两种带 timeout 的 spend 都以真实的 16-byte label 通过远端 Core 31.1 strict policy，pointlock 节省 **54 WU / 14 vB / 14.4% vsize**，交易数仍为一。测试中的两输出 funding 为 197 vB，只是同时提供两个比较 UTXO，不应计作每次 Disprove 固定开销。timeout leaf 在这次测试中被 commitment 覆盖，但没有另行执行 timeout spend。原始报告在 `data/run-disprove-pointlock-core31-regtest.json`。

pointlock 引入以下约束：

- 从 hash-only fraud secret 改为依赖 secp256k1 discrete log/BIP340；
- setup 必须验证 public point 确实绑定正确 false label，并处理 hash-to-scalar rejection、zero 和 x-only parity；
- key-path spend不公开 false label。若后续协议需要从链上抽取 secret，应公开 adaptor presignature；
- key-path 本身不能固定 outputs。若 Disprove 必须强制 burn/slash 到指定目的地，需要对固定交易做 public adaptor presigning 或使用 covenant；
- operator 本来就知道 false label，因而可以自花 connector。只有在“任意 connector spend 都使 Withdraw 失效”时，这与原 hashlock 的 self-sabotage 语义等价。

结论是：pointlock 是已验证、低风险的小优化，但 Assert 每减少 0.001% 都可能超过它的全部收益，优先级应靠后。

## 7. 需要软分叉的方法

### 7.1 CTV、TXHASH、CSFS/APO：优化控制面，不压缩 labels

CTV/template commitments 能替代一部分 deleted-key presigning；TXHASH 提供更灵活的交易字段 commitment；CSFS/APO 改善动态授权和预签交易可重绑定。这些工具能降低 setup、签名组合和 fee-management 复杂度，却不会让 130,128 枚 adaptor completions 从 witness 中消失。

以当前 fixtures 为上限，删除普通 per-input authorization signature 只会给 signed Lamport 节省约 16,965 vB、给 ACW 节省约 12,740 vB，均约 0.1%；adaptor 的每枚 signature 同时承担 digit selection，不能由 CTV 替换。400,000-WU standard transaction limit 也不会因 covenant 自动消失，所以 8-bit adaptor 仍至少需要 23 笔 reveal。

### 7.2 CAT/PAIRCOMMIT：只有改成 trace commitment 才有数量级收益

CAT + SHA256 或 PAIRCOMMIT 可以在 Script 中检查 Merkle/vector commitment，但把每条 binary wire 独立 Merkle 化并不省空间。若每个 wire 的两个 labels 相邻，公开一个 label 仍至少要给 32-byte sibling hash；仅 siblings 就是：

```text
1,041,024 × 32 = 33,312,768 witness bytes ≈ 8.33 MvB
```

这还没算 selected labels、scripts 和 tx shells，已经比 8-bit adaptor 更大。因此 CAT 的正确用途不是“给每个 label 加 Merkle proof”，而是把整段 computation/trace 变成一个 state commitment。

### 7.3 MATT / CCV：最值得做的软分叉原型

MATT 将 execution trace Merkle 化，Assert 只提交 root、initial state 和 claimed final state。发生争议时，operator 展开 k 个子区间，challenger 选择错误区间，重复到单个 transition；最终 leaf Script 只验证这一小步。CCV 让 UTXO 携带并延续动态 state commitment，CAT/PAIRCOMMIT 负责 commitment 运算。

公开原型证明了 `O(log n)` 的交互图；作者给出的 2^32-step 成本为：

- binary search：约 **16,000 vB / 65 tx**；
- 16-ary search：约 **7,000 vB / 17 tx**，但这是尚未实现的估算。

若非常粗略地把本项目约 10^8 gates 当成约 2^27 trace steps，则 binary 路径约 `2×27+1 = 55 tx`、按作者模型外推约 13.5 kvB；16-ary 约 `2×7+1 = 15 tx`、预计不高于约 7 kvB。这些是 E4，不是本项目 benchmark：实际 VM step 可以批量包含多门，leaf verifier 大小、state width、DA 和 fee shell 都会改变结果。

MATT 相对 GC adaptor 的优势是最坏链上 bytes 可能减少约 99% 以上、无需发布百万 labels；代价是 15–55 笔**顺序依赖**交易、相近数量的交互确认阶段、完整 trace DA、在线 challenger 和严格 timeout。它不能与当前 23 笔可并行 reveal 只按“交易数”直接比较。

### 7.4 GSR/direct verifier 与 native STARK opcode

GSR 的 BIP440/441 草案引入按 transaction weight 计费的 varops，以及 0xc2 tapleaf 中更大的 stack elements、更多 stack objects、恢复的 CAT/bit/arithmetic operations。若只拿它包装现有 adaptor，收益仍接近零；只有直接在 Script 中实现 WHIR/STARK verifier，删除整个 GC label 层，才可能得到数量级下降。目前没有本项目的完整 WHIR Script、varops 或 Core benchmark。

专用 `OP_STARK_VERIFY` 更直接：合法 proof 在一笔 spend 中由 consensus verifier 接受，非法 proof 根本不能上链，因此不再需要 Disprove。对本项目 130,128-byte payload，已经 E1 测得的 envelope transport 给出约 33-kvB 的现实量级；但 opcode 的 script/interface、public-input/transaction binding 和 runtime pricing 尚未加入，不能把 33,004 vB当作 native verifier 的 exact total。

Native opcode 的代价是把具体 proof format、参数和 verifier implementation 永久放入共识，增加 DoS、升级和 credible-neutrality 风险。现有提案仍是早期讨论，没有 BIP 或主网 activation path。GSR、CCV、PAIRCOMMIT、CAT、CTV、TXHASH、CSFS 等在本报告日期也都不能当作 Bitcoin mainnet 已部署能力。

## 8. 横向决策表

| 目标 | 首选方法 | 可引用数字 | 成熟度 | 主要阻塞 |
|---|---|---:|---|---|
| 保留当前 GC、当前共识、近期可实现 | 10/11-bit adaptor | 10-bit 1,782,498 vB / 19 tx；11-bit 1,620,499 vB / 18 tx | E2；8/16-bit 交易形状有 E1 | digit-to-binary label delivery 与完整 choice table |
| 当前共识下最小 authenticated transport | ESSPI envelope | **33,004 vB / 2 tx** | E1 transport | 不是 GC label Assert；完整 DA-DAG/secondary BitVMX 未计 |
| hash-only GC input auth | WOTS translation / ACW | ACW **11,882,711 vB / 132 tx** | ACW E1；translation E3/E4 | 仍为 MvB；大离线表/translation gadget |
| 防止 `M=7` 线性重复 | Mosaic correlation | one-keyset 而非 seven-keysets | E3 | 本项目 soldering/setup 未实现 |
| 现有 Disprove 小优化 | pointlock | **83 vB**，比本项目同 timeout hashlock 少 14 vB | E1 | DLog 假设、output binding/secret extraction |
| 软分叉后压低最坏 dispute bytes | MATT/CCV + vector commitment | 作者 2^32-step：16 kvB/65 tx；16-ary 7 kvB/17 tx | E3/E4 | 软分叉、顺序轮数、DA、在线 challenger |
| 软分叉后一笔验证 | direct GSR 或 native STARK | payload 量级约 33 kvB；无本项目 verifier total | E4 | 共识/DoS面、实现与激活成熟度 |
| 理论极小 Assert/Disprove | PIPEs | one hash / one signature | E3 concept | 约 338-TB WE artifact，假设和 setup 限制 |

## 9. 推荐实现路线

### P0：先删除错误结论

把 `unverified_reveal_and_response_on_demand` 永久标成“非标准、未绑定、仅容量实验”。任何新方案都必须回答三个问题：谁授权 spend、首次 payload 被什么 commitment 绑定、后续 Script 如何证明 response 对应同一 payload。

### P1：完成 10/11-bit adaptor，而不是直接部署 16-bit

1. 实现完整 `2^k` choices，而非只生成被选 completion；
2. 实现 digit secret 到 `k` 条 binary labels 的唯一释放；
3. 加相反-label、混合-digit、padding-bit、table truncation 和 equivocation negatives；
4. 把 Mosaic/soldering 纳入 `M=7`；
5. 在远端 Core 对 10/11-bit 完成真实签名、funding、all reveals、completion join 和 Disprove/Take2 重放。

11-bit 是当前首选候选：相对基线少 27.27%，交易从 24 降至 18，表为 12.598 GB/keyset；如果 setup/storage 更敏感，则选择 10-bit 的 6.929 GB/keyset 和 20% 链上收益。

### P2：把 ESSPI 做成独立 architecture branch

不要把 envelope fixture 接到当前 GC 后就声称完成。应先明确选择：

- 用 ESSPI/BitVMX 直接验证 STARK input/proof；或
- 设计新的 commitment-to-selected-label bridge。

前者更符合 ESSPI 原论文，也是达到 33-kvB transport 的最短路径。下一里程碑应序列化完整 DA-DAG 和 secondary BitVMX 的一个最小参数实例，报告 normal/challenged/worst-case 三组交易数、vB、顺序确认轮数和 bond。

### P3：补齐完整 GC transaction graph

无论选 8/10/11-bit，都需构造：ChallengeAssert、所有 Assert reveals、completion join、平衡的 Disprove/Take2 leaves、timeouts、anchors/CPFP、fee inputs 和最终 settlement。Core cluster rejection已经证明 funding 与大 reveal 不能默认作为一个未确认 package；确认阶段必须成为协议参数。

### P4：软分叉研究集中在 MATT，而非 CTV-only

CTV/TXHASH/CSFS 可作为 setup/control-plane 辅助项，但不应在论文中宣传成 input compression。真正值得做的原型是把 WHIR verifier 编译为 state machine，测量：state width、每 step/批 step 的 Script、binary/16-ary commitment opening、完整 dispute graph 和 timeout latency。

### P5：最后再合入 pointlock

只有在确定 protocol 不要求链上公开 false label、且任意 connector spend 都能使 operator 的 Withdraw 失效时，才用 direct pointlock。若 outputs 必须固定，改用公开 adaptor presignature，并单独验证 nonce、安全分发和 fee-bumping。

## 10. 仍未解决的关键问题

1. **完整成本未知。** 现有 exact numbers 是 funding/reveal/transport/Disprove 组件，不是完整 Assert/Disprove protocol graph。
2. **Wider digit 的 label semantics 未实现。** 这是 10/11/16-bit 方案的致命前置条件，不是工程小项。
3. **多副本 soldering 未实现。** 没有 Mosaic 或等价机制时，`M=7` 可能把 input-auth 成本线性放大。
4. **ESSPI 的 GC 适配不存在。** 33,004 vB 不能替代 selected labels；完整 ESSPI 也没有可引用的总 vB。
5. **DA 与交互活性。** ESSPI/MATT 都把一部分安全性移到链外数据可用性、在线 challenger、timeouts 和 fee competition。
6. **主网 relay 不等于 regtest acceptance。** E1 证明 Core 规则接受和能被本地 miner 打包，不证明公网节点拓扑、矿工政策、长期手续费或抗审查性。
7. **量子口径。** Adaptor/pointlock/Bitcoin transaction signatures 都依赖 secp256k1；即使底层 WHIR/hash garbling是 hash-based，也不能把端到端协议称为 post-quantum。
8. **软分叉状态。** 草案的 `Complete`/`Draft` 状态都不等于 mainnet activation，成本表必须把 current-consensus 与 hypothetical-softfork 分列。

## 11. 结论

对当前代码，最可信的直接改进不是压缩 script shell，而是提高每枚 adaptor completion 的 payload。16-bit 的交易层减半已被 Core 证明，但离线表过大且 label mapping 未完成；**10/11-bit 是下一步正确工程选择**。

若研究目标从“保留 garbled STARK verifier”改为“尽可能降低当前共识下的 signed proof publication”，ESSPI envelope 是数量级最好的结果：**33,004 vB / 2 transactions**。它应作为新的 BitVMX/DA architecture branch，而不是伪装成 drop-in GC Assert。

Disprove 从 97 vB 降到 83 vB 已经足够，继续优化的边际价值很低。长期若允许软分叉，应优先研究 MATT/CCV 的 trace-root + interactive localization，因为它真正删除百万 labels；CTV/TXHASH/CSFS 单独使用只改善 control plane。Native STARK verification 是理论终点，但当前不具备足够的规范、benchmark 与激活成熟度。

## 12. 可复核材料

- `whir-gc/tests/adaptor_tx_cost.rs`：8/10/11/12/16-bit exact sweep；16-bit 全量真实签名 fixture。
- `paper/data/run-adaptor-wider-tx-cost.txt`：上述两个 wider-adaptor 测试在远端当前源码上的归档输出。
- `whir-gc/tests/esspi_envelope_cost.rs`：130,128-byte signed P2TR envelope。
- `whir-gc/tests/disprove_pointlock_cost.rs`：hashlock 与 pointlock 的同 timeout 对比。
- `paper/data/run-input-fixture-core31-regtest.sh`：8-bit、16-bit adaptor 与 ACW Core harness。
- `paper/data/run-esspi-envelope-core31-regtest.sh`：envelope Core harness。
- `paper/data/run-disprove-pointlock-core31-regtest.sh`：Disprove Core harness。
- `paper/data/run-adaptor16-core31-regtest.json`、`run-esspi-envelope-core31-regtest.json`、`run-disprove-pointlock-core31-regtest.json`：远端 E1 原始汇总。

## 13. 一手来源

1. BitVM3: <https://eprint.iacr.org/2026/933>
2. Robin Linus, wider adaptor digits: <https://gist.github.com/RobinLinus/0fc7405ad7485c35465efb7996a7b014>
3. Glock: <https://eprint.iacr.org/2025/1485>
4. WOTS-to-Lamport translation: <https://eprint.iacr.org/2026/1684>
5. Antichain Winternitz: <https://eprint.iacr.org/2026/1568>
6. Mosaic: <https://eprint.iacr.org/2026/812>
7. TinyLabels: <https://eprint.iacr.org/2024/2048>
8. ESSPI: <https://arxiv.org/abs/2503.02772>
9. Bitcoin PIPEs v2: <https://eprint.iacr.org/2026/186>
10. BIP341: <https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>
11. BIP342: <https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki>
12. Bitcoin Core 31.1 policy constants: <https://github.com/bitcoin/bitcoin/blob/v31.1/src/policy/policy.h>
13. Bitcoin Core 31.1 witness standardness: <https://github.com/bitcoin/bitcoin/blob/v31.1/src/policy/policy.cpp>
14. BIP119 CTV: <https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki>
15. BIP346 TXHASH: <https://github.com/bitcoin/bips/blob/master/bip-0346.md>
16. BIP348 CSFS: <https://bitcoin.org/bip/348/>
17. BIP347 CAT: <https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki>
18. BIP442 PAIRCOMMIT: <https://bitcoin.org/bip/442/>
19. BIP443 CCV: <https://github.com/bitcoin/bips/blob/master/bip-0443.mediawiki>
20. MATT challenge reference implementation: <https://github.com/halseth/mattlab/blob/main/docs/challenge.md>
21. MATT cost discussion: <https://delvingbitcoin.org/t/games-in-the-head-and-fraud-proofs-for-the-plebs/446>
22. BIP440 varops: <https://bitcoin.org/bip/440/>
23. BIP441 GSR tapleaf: <https://bitcoin.org/bip/441/>
24. Early native STARK opcode discussion: <https://delvingbitcoin.org/t/proposal-op-stark-verify-native-stark-proof-verification-in-bitcoin-script/2056>
