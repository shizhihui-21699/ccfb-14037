using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BreachGuard.Detection;

namespace BreachGuard.Protection;

/// <summary>
/// 秘密掩码(BREACH 的根治手段之一):
/// 响应中的秘密不再以明文出现,而是替换为每请求随机的占位符;
/// 真实值以 XOR(masked, mask) 形式下发,由注入的内联脚本在客户端还原后写回 DOM。
/// masked 与 mask 每次都重新随机,攻击者控制的反射内容永远无法与秘密的
/// 任何稳定字节串形成 LZ77 匹配,压缩长度预言机随之失效。
/// 带宽代价:每个秘密约 2 段 base64 + 一段一次性脚本(可再被 gzip 压缩)。
/// </summary>
public static class SecretMasker
{
    private const string RestoreJs =
        "var T=new TextDecoder(),i;for(i=0;i<D.length;i++)(function(d){" +
        "var mb=Uint8Array.from(atob(d[1]),function(c){return c.charCodeAt(0)});" +
        "var kb=Uint8Array.from(atob(d[2]),function(c){return c.charCodeAt(0)});" +
        "var o=new Uint8Array(mb.length),j;for(j=0;j<mb.length;j++)o[j]=mb[j]^kb[j%kb.length];" +
        "var s=T.decode(o),ph=d[0],e,a,n;" +
        "var all=document.querySelectorAll('*');" +
        "for(e=0;e<all.length;e++){var el=all[e];for(a=0;a<el.attributes.length;a++){" +
        "var at=el.attributes[a];if(at.value.indexOf(ph)>=0)at.value=at.value.split(ph).join(s);}}" +
        "var w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);" +
        "while(n=w.nextNode()){if(n.nodeValue.indexOf(ph)>=0)n.nodeValue=n.nodeValue.split(ph).join(s);}" +
        "})(D[i]);";

    public static string Mask(string html, IReadOnlyList<SecretHit> secrets)
    {
        var distinct = secrets.Select(s => s.Value)
            .Where(v => v.Length >= 6)
            .Distinct(StringComparer.Ordinal)
            .OrderByDescending(v => v.Length) // 先替换长的,避免子串误替换
            .ToList();
        if (distinct.Count == 0)
            return html;

        var entries = new List<string[]>(distinct.Count);
        var sb = new StringBuilder(html);
        for (var i = 0; i < distinct.Count; i++)
        {
            var secretBytes = Encoding.UTF8.GetBytes(distinct[i]);
            var mask = RandomNumberGenerator.GetBytes(secretBytes.Length);
            var masked = new byte[secretBytes.Length];
            for (var j = 0; j < secretBytes.Length; j++)
                masked[j] = (byte)(secretBytes[j] ^ mask[j]);

            // 占位符每请求随机,攻击者无法预知也就无法让反射内容与之匹配
            var placeholder = "BGz" + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant() + i;
            sb.Replace(distinct[i], placeholder);
            entries.Add(new[] { placeholder, Convert.ToBase64String(masked), Convert.ToBase64String(mask) });
        }

        var script = "<script>(function(){var D=" + JsonSerializer.Serialize(entries) + ";" + RestoreJs + "})();</script>";
        var result = sb.ToString();
        var bodyEnd = result.LastIndexOf("</body>", StringComparison.OrdinalIgnoreCase);
        return bodyEnd >= 0 ? result.Insert(bodyEnd, script) : result + script;
    }
}
