using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace OAuthGrantExchangeIntegration.Server;

public class CreateDelegatedAccessTokenPayloadModel
{
    public string Sub { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public string OriginalClientId { get; set; } = string.Empty;
    public ClaimsIdentity? ClaimsIdentity { get; set; }

    public X509Certificate2? SigningCredentials { get; set; }
}
