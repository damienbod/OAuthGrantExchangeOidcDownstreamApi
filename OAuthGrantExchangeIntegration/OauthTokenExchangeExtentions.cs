using System.Security.Cryptography;
using System.Text;

namespace OAuthGrantExchangeIntegration;

public static class OauthTokenExchangeExtentions
{
    public static string ToSha256(string text)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(text);
        var hash = sha256.ComputeHash(bytes);

        return Convert.ToBase64String(hash);
    }
}

