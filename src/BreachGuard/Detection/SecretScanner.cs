namespace BreachGuard.Detection;

/// <summary>用配置的秘密模式扫描响应体,返回命中(含值,仅供掩码使用)。</summary>
public static class SecretScanner
{
    public static List<SecretHit> Find(string html, IEnumerable<SecretPattern> patterns)
    {
        var hits = new List<SecretHit>();
        foreach (var pattern in patterns)
        {
            foreach (System.Text.RegularExpressions.Match m in pattern.Regex.Matches(html))
            {
                var g = m.Groups["secret"];
                if (g.Success && g.Value.Length >= 8)
                    hits.Add(new SecretHit(pattern.Name, g.Index, g.Value));
            }
        }
        return hits;
    }
}
