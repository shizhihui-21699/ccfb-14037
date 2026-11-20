# BreachGuard — 压缩长度泄露(BREACH/CRIME)检测与防护组件

针对"响应压缩 + 攻击者可控反射 + 页面内秘密"三者共现时的长度侧信道:
攻击者诱导用户反复发请求,观察 gzip 后响应长度的细微变化,逐字符猜出 CSRF 令牌等秘密。

```
src/BreachGuard/      检测 + 防护中间件库(接入现有 ASP.NET Core 服务)
samples/DemoApp/      演示服务:/vulnerable(无防护) /padded(仅填充) /protected(掩码+填充)
tools/BreachAttack/   攻击 PoC:真实利用长度预言机逐字符恢复令牌,验证防护前后效果
```

## 快速复现

```bash
dotnet build BreachGuard.slnx
cd samples/DemoApp && dotnet run          # 监听 launchSettings 中的端口(默认 5163)

# 攻击无防护端点 —— 32 位令牌数秒内完整恢复
dotnet run --project tools/BreachAttack -- \
  --url http://localhost:5163/vulnerable/search --length 32 \
  --alphabet 0123456789abcdef --expect a3f8c2d91e4b6075f1a2c3d4e5f60718

# 攻击 /padded、/protected —— 引导阶段即失败
# 检测报告
curl http://localhost:5163/_breachguard/findings
```

## 检测:找出可被利用的组合

`BreachGuardMiddleware` 缓冲 HTML 响应后做两类分析(见 `Detection/`):

- **反射分析** `ReflectionAnalyzer`:攻击者可控入口不止 URL 参数 —— 查询串、
  可配置的请求头(User-Agent/Referer/Accept-Language/X-Forwarded-For)、Cookie
  都会被收集,在响应中查找原文或 HTML 编码后的反射位置。评论等存储型反射在页面
  渲染后同样会被命中。
- **秘密扫描** `SecretScanner`:可配置正则(命名组 `secret`),内置 CSRF 令牌、
  JWT、api-key 三类;秘密不限于令牌,自行添加模式即可。
- **可利用性判定**:反射点出现在秘密之前且距离 < 32KB(DEFLATE 滑动窗口),
  才构成可利用组合,记入 `FindingStore` 并输出告警日志;
  `GET /_breachguard/findings` 返回 JSON 报告(路径、反射源、秘密类型、修复建议)。

## 防护:不关压缩、不明显增加带宽

按路径配置级别(`ProtectionFor`),**只对含秘密的页面生效**,其余页面零开销:

| 级别 | 手段 | 效果 |
|---|---|---|
| `LengthHiding` | 随机长度注释填充(基础均匀分布 + 随机桶跳变) | 把长度噪声 std 推到 ~400B,攻击者每候选需 ~10⁴–10⁵ 样本才能平均出信号 —— 大幅提高成本,但**理论上仍可被平均抵消**,只作纵深防御 |
| `SecretMasking` | 秘密掩码(含 LengthHiding) | **根治**:秘密不再以明文进入压缩流。每请求生成随机 mask,页面只携带 `XOR(secret, mask)` 与 `mask`(两者每次都重新随机)和随机占位符,内联脚本在客户端还原写回 DOM。攻击者的反射内容没有任何稳定字节串可匹配,长度预言机失效,且带宽代价仅每秘密两段 base64 + 一段可压缩脚本 |

其他可叠加的防线(不在本组件内):对敏感端点限流、CSRF 令牌每请求轮换、
把秘密移出含反射的响应。

## 攻击 PoC 的技术要点(`tools/BreachAttack`)

真实可用的恢复程序,处理了实际攻击中的四个难点:

1. **冷启动**:LZ77 匹配至少 3 字符,前 4 位用 16⁴ 穷举引导(`--bootstrap`)。
2. **信号放大**:探测串同时放进 URL 参数和 User-Agent(页面两个反射入口都被利用)。
3. **对齐扫描**:Huffman 逐位打包使单字符信号是子字节级的,且随页面内容波动。
   每个候选用一组**固定的随机对齐串**(所有候选共用,不引入方差;随机内容不可压缩,
   真正改变 DEFLATE 解析)取平均,抵消系统性偏差。重复字符(如 `~~~`)会被压成回引,
   改变不了对齐,是无效填充。
4. **束搜索**:单位置会出现平局/反转,按"相对兄弟候选的累计赤字"评分保留多条
   候选前缀(`--beam`),正确路径每步赤字≈0,局部噪声不会致命。

`--samples N` 控制每候选的对齐样本数,也是对抗随机填充的唯一手段(取平均)。

## 实测结果(本机,.NET 11 + gzip)

| 目标 | 结果 |
|---|---|
| `/vulnerable` | **32/32 字符全部恢复,约 2 秒**(含 65536 次引导请求) |
| `/padded`(仅填充) | 64 样本/候选仍在引导阶段失败;按噪声 std 估算需每候选 ~10⁴ 以上样本,实际不可行 |
| `/protected`(掩码+填充) | 任何样本量均失败 —— 秘密不在压缩流中,长度不携带信息 |

## 已知限制

- 中间件只处理 `text/html` 的 200 响应;表单 body 的反射未纳入检测(需读取请求体,留给接入方按路由开启)。
- 掩码脚本依赖 `TextDecoder`(全现代浏览器可用);秘密若出现在 `<script>` 字符串字面量中,
  还原逻辑同样生效(占位符替换),但请确保占位符字符集(`BGz`+hex)不与现有代码冲突。
- 长度填充是概率性防御,单独使用不等于安全;掩码才是根治。
