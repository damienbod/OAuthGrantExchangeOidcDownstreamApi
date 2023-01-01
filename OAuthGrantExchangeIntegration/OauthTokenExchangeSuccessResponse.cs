using System.Text.Json.Serialization;

namespace OAuthGrantExchangeIntegration;

public class OauthTokenExchangeSuccessResponse
{
    [JsonPropertyName(OAuthGrantExchangeConsts.RESPONSE_ACCESS_TOKEN)]
    public string access_token { get; set; } = string.Empty;

    /// <summary>
    /// urn:ietf:params:oauth:token-type:access_token
    /// urn:ietf:params:oauth:token-type:refresh_token
    /// urn:ietf:params:oauth:token-type:id_token
    /// urn:ietf:params:oauth:token-type:saml1
    /// urn:ietf:params:oauth:token-type:saml2
    /// </summary>
    [JsonPropertyName(OAuthGrantExchangeConsts.RESPONSE_ISSUED_TOKEN_TYPE)]
    public string issued_token_type { get; set; } = string.Empty;

    [JsonPropertyName(OAuthGrantExchangeConsts.RESPONSE_TOKEN_TYPE)]
    public string token_type { get; set; } = string.Empty;

    [JsonPropertyName(OAuthGrantExchangeConsts.RESPONSE_EXPIRES_IN)]
    public int expires_in { get; set; }

    [JsonPropertyName(OAuthGrantExchangeConsts.SCOPE)]
    public string? scope { get; set; }

    [JsonPropertyName(OAuthGrantExchangeConsts.RESPONSE_REFRESH_TOKEN)]
    public string? refresh_token { get; set; }
}
