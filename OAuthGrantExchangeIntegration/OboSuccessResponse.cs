using System.Text.Json.Serialization;

namespace OAuthGrantExchangeIntegration;

public class OboSuccessResponse
{
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";
    [JsonPropertyName("scope")]
    public string Scope { get; set; } = string.Empty;

    // Consider implementing token exchange specs instead of MS OBO
    //[JsonPropertyName("issued_token_type")]
    //public string IssuedTokenType { get; set; } = "urn:ietf:params:oauth:token-type:access_token";

}
