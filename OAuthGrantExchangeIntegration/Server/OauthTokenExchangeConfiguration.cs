using System.Text.Json.Serialization;

namespace OAuthGrantExchangeIntegration.Server;

public class OauthTokenExchangeConfiguration
{
    // assertion parameter token validation
    [JsonPropertyName("AccessTokenMetadataAddress")]
    public string AccessTokenMetadataAddress { get; set; } = string.Empty;
    [JsonPropertyName("AccessTokenAuthority")]
    public string AccessTokenAuthority { get; set; } = string.Empty;
    [JsonPropertyName("AccessTokenAudience")]
    public string AccessTokenAudience { get; set; } = string.Empty;

    // request parameters
    [JsonPropertyName("ClientId")]
    public string ClientId { get; set; } = string.Empty;
    [JsonPropertyName("ClientSecret")]
    public string ClientSecret { get; set; } = string.Empty;
    [JsonPropertyName("ScopeForNewAccessToken")]
    public string ScopeForNewAccessToken { get; set; } = string.Empty;

    // new token claims
    [JsonPropertyName("AudienceForNewAccessToken")]
    public string AudienceForNewAccessToken { get; set; } = string.Empty;
    public string IssuerForNewAccessToken { get; set; }
}
