using BreachGuard.Detection;
using Microsoft.AspNetCore.Builder;

namespace BreachGuard;

public static class BreachGuardExtensions
{
    /// <summary>
    /// 注册 BreachGuard。放在 UseResponseCompression() 之后。
    /// <code>
    /// app.UseResponseCompression();
    /// app.UseBreachGuard(o => o.ProtectionFor = c =>
    ///     c.Request.Path.StartsWithSegments("/account") ? ProtectionMode.SecretMasking : ProtectionMode.None);
    /// </code>
    /// </summary>
    public static IApplicationBuilder UseBreachGuard(this IApplicationBuilder app,
        Action<BreachGuardOptions>? configure = null)
    {
        var options = new BreachGuardOptions();
        configure?.Invoke(options);
        return app.UseMiddleware<BreachGuardMiddleware>(options, new FindingStore());
    }
}
