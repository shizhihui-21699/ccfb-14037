using System.Collections.Concurrent;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace BreachGuard.Detection;

/// <summary>一处攻击者可控值在响应中的反射。</summary>
public sealed record ReflectedValue(string Source, string Name, int Offset);

/// <summary>响应中命中的秘密。Value 只用于掩码,绝不写入报告。</summary>
public sealed record SecretHit(string Kind, int Offset, string Value);

public sealed class Finding
{
    public required string Path { get; init; }
    public SortedSet<string> ReflectedFrom { get; } = new(StringComparer.Ordinal);
    public List<string> SecretKinds { get; } = new();
    /// <summary>反射点出现在秘密之前且距离 &lt; 32KB(LZ77 窗口),构成可利用组合。</summary>
    public bool Exploitable { get; set; }
    public int Hits { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public string Recommendation =>
        Exploitable
            ? "攻击者可控输入与秘密在同一压缩响应内共现:启用 SecretMasking,或将秘密移出该响应/每请求轮换。"
            : "未发现可利用组合。";
}

public sealed class FindingStore
{
    private readonly ConcurrentDictionary<string, Finding> _findings = new(StringComparer.Ordinal);

    public void Record(string path, IReadOnlyList<ReflectedValue> reflections,
        IReadOnlyList<SecretHit> secrets, ILogger logger)
    {
        var finding = _findings.GetOrAdd(path, p => new Finding { Path = p });
        lock (finding)
        {
            foreach (var r in reflections)
                finding.ReflectedFrom.Add($"{r.Source}:{r.Name}");
            foreach (var s in secrets)
                if (!finding.SecretKinds.Contains(s.Kind))
                    finding.SecretKinds.Add(s.Kind);

            // LZ77 只能向后引用 32KB 窗口:反射必须在秘密之前且距离窗口内。
            bool exploitable = reflections.Count > 0 && secrets.Count > 0 &&
                reflections.Any(r => secrets.Any(s => r.Offset < s.Offset && s.Offset - r.Offset < 32768));
            if (exploitable && !finding.Exploitable)
                logger.LogWarning(
                    "BREACH 可利用组合: {Path} 反射源 [{Sources}] 与秘密 [{Kinds}] 同页共现",
                    path, string.Join(",", finding.ReflectedFrom), string.Join(",", finding.SecretKinds));
            finding.Exploitable |= exploitable;
            finding.Hits++;
            finding.LastSeen = DateTimeOffset.UtcNow;
        }
    }

    public IReadOnlyList<Finding> Snapshot() =>
        _findings.Values.OrderByDescending(f => f.Exploitable).ThenBy(f => f.Path).ToList();
}
