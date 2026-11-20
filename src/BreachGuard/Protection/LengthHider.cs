using System.Security.Cryptography;

namespace BreachGuard.Protection;

/// <summary>
/// 长度隐藏:向含秘密的页面追加随机长度注释,扰乱压缩后长度与猜测之间的相关性。
/// 注意:这是概率性防御,足够多的样本取平均仍可抵消(本组件的攻击 PoC 可演示),
/// 因此只作为 SecretMasking 之外的纵深防御,或无法掩码时的成本提高手段。
/// 填充使用随机字母数字,压缩率约 6 bit/字符,带宽代价可控。
/// </summary>
public static class LengthHider
{
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    public static string Pad(string html, BreachGuardOptions options)
    {
        var length = RandomNumberGenerator.GetInt32(0, options.PadMaxChars)
                   + options.PadBucketChars * RandomNumberGenerator.GetInt32(0, options.PadMaxBuckets + 1);
        if (length <= 0)
            return html;

        var chars = new char[length];
        for (var i = 0; i < length; i++)
            chars[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];

        var comment = "<!--" + new string(chars) + "-->";
        var bodyEnd = html.LastIndexOf("</body>", StringComparison.OrdinalIgnoreCase);
        return bodyEnd >= 0 ? html.Insert(bodyEnd, comment) : html + comment;
    }
}
