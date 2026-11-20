using System.Text;
using System.Text.Json;
using BreachGuard.Detection;
using BreachGuard.Protection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace BreachGuard;

/// <summary>
/// 压缩长度泄露(BREACH/CRIME)检测与防护中间件。
/// 必须注册在 ResponseCompression 之后(app.UseResponseCompression(); app.UseBreachGuard();),
/// 这样改写发生在压缩之前。
/// </summary>
public sealed class BreachGuardMiddleware
{
    private readonly RequestDelegate _next;
    private readonly BreachGuardOptions _options;
    private readonly FindingStore _store;
    private readonly ILogger<BreachGuardMiddleware> _logger;

    public BreachGuardMiddleware(RequestDelegate next, BreachGuardOptions options,
        FindingStore store, ILogger<BreachGuardMiddleware> logger)
    {
        _next = next;
        _options = options;
        _store = store;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        if (context.Request.Path.Equals(_options.ReportPath, StringComparison.OrdinalIgnoreCase))
        {
            context.Response.ContentType = "application/json; charset=utf-8";
            await context.Response.WriteAsync(
                JsonSerializer.Serialize(_store.Snapshot(), new JsonSerializerOptions { WriteIndented = true }));
            return;
        }

        var mode = _options.ProtectionFor(context);
        if (!_options.DetectionEnabled && mode == ProtectionMode.None)
        {
            await _next(context);
            return;
        }

        var originalBody = context.Response.Body;
        var buffer = new MemoryStream();
        context.Response.Body = buffer;
        try
        {
            await _next(context);
        }
        catch
        {
            context.Response.Body = originalBody;
            buffer.Dispose();
            throw;
        }

        var contentType = context.Response.ContentType ?? string.Empty;
        var isHtml = context.Response.StatusCode == StatusCodes.Status200OK
                     && contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase)
                     && !context.Response.Headers.ContainsKey("Content-Encoding");

        if (!isHtml)
        {
            context.Response.Body = originalBody;
            buffer.Position = 0;
            await buffer.CopyToAsync(originalBody);
            buffer.Dispose();
            return;
        }

        buffer.Position = 0;
        string html;
        using (var reader = new StreamReader(buffer, Encoding.UTF8, leaveOpen: true))
            html = await reader.ReadToEndAsync();
        buffer.Dispose();

        var secrets = SecretScanner.Find(html, _options.SecretPatterns);

        if (_options.DetectionEnabled)
        {
            var reflections = ReflectionAnalyzer.Find(context, html, _options);
            if (secrets.Count > 0 || reflections.Count > 0)
                _store.Record(context.Request.Path.Value ?? "/", reflections, secrets, _logger);
        }

        // 只对含秘密的页面施加防护,带宽代价最小化
        if (secrets.Count > 0)
        {
            if (mode >= ProtectionMode.SecretMasking)
                html = SecretMasker.Mask(html, secrets);
            if (mode >= ProtectionMode.LengthHiding)
                html = LengthHider.Pad(html, _options);
        }

        context.Response.Body = originalBody;
        context.Response.Headers.Remove("Content-Length");
        var bytes = Encoding.UTF8.GetBytes(html);
        await originalBody.WriteAsync(bytes);
    }
}
