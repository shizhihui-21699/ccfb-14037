using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;

namespace BreachGuard;

/// <summary>防护级别。None &lt; LengthHiding &lt; SecretMasking(含 LengthHiding)。</summary>
public enum ProtectionMode
{
    None = 0,
    /// <summary>仅随机长度填充(提高攻击成本,可被大样本平均抵消,只作纵深防御)。</summary>
    LengthHiding = 1,
    /// <summary>秘密掩码(每请求随机化,根治长度预言机)+ 长度填充。</summary>
    SecretMasking = 2,
}

public sealed record SecretPattern(string Name, Regex Regex);

public sealed class BreachGuardOptions
{
    /// <summary>是否开启检测(反射点 + 秘密共现分析)。</summary>
    public bool DetectionEnabled { get; set; } = true;

    /// <summary>按请求决定防护级别,默认不防护(仅检测)。</summary>
    public Func<HttpContext, ProtectionMode> ProtectionFor { get; set; } = _ => ProtectionMode.None;

    /// <summary>秘密模式。必须含命名组 (?&lt;secret&gt;...)。</summary>
    public IList<SecretPattern> SecretPatterns { get; } = new List<SecretPattern>
    {
        new("csrf-token", new Regex(
            "name=[\"'][^\"']*(?:csrf|xsrf|authenticity|_token)[^\"']*[\"'][^>]*?value=[\"'](?<secret>[^\"']{8,})[\"']",
            RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        new("jwt", new Regex(
            "(?<secret>eyJ[A-Za-z0-9_\\-]{8,}\\.[A-Za-z0-9_\\-]{8,}\\.[A-Za-z0-9_\\-]{8,})",
            RegexOptions.Compiled)),
        new("api-key", new Regex(
            "(?:api[_-]?key|apikey|access[_-]?token)[\"'\\s:=]+(?<secret>[A-Za-z0-9_\\-]{16,})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled)),
    };

    /// <summary>检测时纳入反射分析的请求头(攻击者可控制的入口不止 URL 参数)。</summary>
    public IList<string> ReflectionHeaders { get; } = new List<string>
    {
        "User-Agent", "Referer", "Accept-Language", "X-Forwarded-For",
    };

    /// <summary>短于该长度的反射值不计(避免噪声)。</summary>
    public int MinReflectionLength { get; set; } = 4;

    /// <summary>检测报告路径。</summary>
    public string ReportPath { get; set; } = "/_breachguard/findings";

    // ---- 长度填充参数(只作用于含秘密的页面,控制带宽代价) ----
    /// <summary>基础随机填充上限(字符数,均匀分布)。</summary>
    public int PadMaxChars { get; set; } = 600;
    /// <summary>每个随机桶的填充字符数。</summary>
    public int PadBucketChars { get; set; } = 300;
    /// <summary>随机桶数量上限(0..N 桶),让均值难以被少量样本估计。</summary>
    public int PadMaxBuckets { get; set; } = 4;
}
