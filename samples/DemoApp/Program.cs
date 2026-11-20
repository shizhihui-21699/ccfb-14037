using System.Net;
using BreachGuard;
using Microsoft.AspNetCore.ResponseCompression;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddResponseCompression(o =>
{
    o.EnableForHttps = true;
    o.MimeTypes = ResponseCompressionDefaults.MimeTypes.Concat(new[] { "text/html" });
});
builder.Logging.SetMinimumLevel(LogLevel.Warning);

var app = builder.Build();

// 顺序关键:先压缩中间件,BreachGuard 在其内侧运行,改写发生在压缩之前
app.UseResponseCompression();
app.UseBreachGuard(o =>
{
    o.ProtectionFor = c =>
    {
        if (c.Request.Path.StartsWithSegments("/protected")) return ProtectionMode.SecretMasking;
        if (c.Request.Path.StartsWithSegments("/padded")) return ProtectionMode.LengthHiding;
        return ProtectionMode.None; // /vulnerable 及其余路径:仅检测
    };
});

// 演示秘密:站点防伪令牌。真实应用中来自每台服务器/每会话的令牌服务。
const string CsrfToken = "a3f8c2d91e4b6075f1a2c3d4e5f60718";

string SearchPage(string q, string ua) => $"""
<!doctype html>
<html><head><meta charset="utf-8"><title>站内搜索</title></head>
<body>
<h1>站内搜索</h1>
<p>你搜索的是:{WebUtility.HtmlEncode(q)}</p>
<form method="get" action="">
  <input name="q" value="{WebUtility.HtmlEncode(q)}">
  <button>搜索</button>
</form>
<section>共 0 条结果。</section>
<form method="post" action="/account/email">
  <input type="hidden" name="csrf_token" value="{CsrfToken}">
  <label>新邮箱 <input name="email"></label>
  <button>修改邮箱</button>
</form>
<footer>UA: {WebUtility.HtmlEncode(ua)}</footer>
</body></html>
""";

foreach (var prefix in new[] { "/vulnerable", "/padded", "/protected" })
{
    app.MapGet(prefix + "/search", (HttpContext ctx, string? q) =>
        Results.Text(SearchPage(q ?? "", ctx.Request.Headers.UserAgent.ToString()), "text/html"));
}

app.MapGet("/", () => Results.Text("""
<!doctype html><html><head><meta charset="utf-8"><title>BREACH 演示</title></head><body>
<h1>压缩长度泄露演示</h1>
<ul>
  <li><a href="/vulnerable/search?q=test">/vulnerable/search</a> — 无防护</li>
  <li><a href="/padded/search?q=test">/padded/search</a> — 仅随机填充</li>
  <li><a href="/protected/search?q=test">/protected/search</a> — 掩码 + 填充</li>
  <li><a href="/_breachguard/findings">/_breachguard/findings</a> — 检测报告</li>
</ul>
</body></html>
""", "text/html"));

app.Run();
