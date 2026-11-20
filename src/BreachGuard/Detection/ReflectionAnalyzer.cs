using System.Net;
using Microsoft.AspNetCore.Http;

namespace BreachGuard.Detection;

/// <summary>
/// 反射分析:收集请求中攻击者可控的值(query / 指定请求头 / cookie),
/// 在响应 HTML 里查找原文或 HTML 编码后的出现位置。
/// 覆盖"藏在请求头、链接参数"里的可控内容;评论类存储型反射在渲染页面时同样会被命中。
/// </summary>
public static class ReflectionAnalyzer
{
    public static List<ReflectedValue> Find(HttpContext context, string html, BreachGuardOptions options)
    {
        var found = new List<ReflectedValue>();

        void Check(string source, string name, string? value)
        {
            if (string.IsNullOrEmpty(value) || value.Length < options.MinReflectionLength)
                return;
            var offset = html.IndexOf(value, StringComparison.Ordinal);
            if (offset < 0)
            {
                var encoded = WebUtility.HtmlEncode(value);
                if (!string.Equals(encoded, value, StringComparison.Ordinal))
                    offset = html.IndexOf(encoded, StringComparison.Ordinal);
            }
            if (offset >= 0)
                found.Add(new ReflectedValue(source, name, offset));
        }

        foreach (var (key, value) in context.Request.Query)
            Check("query", key, value.ToString());

        foreach (var header in options.ReflectionHeaders)
            if (context.Request.Headers.TryGetValue(header, out var hv))
                Check("header", header, hv.ToString());

        foreach (var (key, value) in context.Request.Cookies)
            Check("cookie", key, value);

        return found;
    }
}
