using System.Diagnostics.Contracts;
using System.Net;
using System.Text;
using System;
using System.Text.Json.Serialization;
using static System.Collections.Specialized.BitVector32;

namespace OAuthGrantExchangeIntegration;

public class OauthTokenExchangeSuccessResponse
{
    [JsonPropertyName("access_token")]
    public string access_token { get; set; } = string.Empty;

    /// <summary>
    /// urn:ietf:params:oauth:token-type:access_token
    /// urn:ietf:params:oauth:token-type:refresh_token
    /// urn:ietf:params:oauth:token-type:id_token
    /// urn:ietf:params:oauth:token-type:saml1
    /// urn:ietf:params:oauth:token-type:saml2
    /// </summary>
    [JsonPropertyName("issued_token_type")]
    public string issued_token_type { get; set; } = string.Empty;

    [JsonPropertyName("token_type")]
    public string token_type { get; set; } = string.Empty;

    [JsonPropertyName("expires_in")]
    public int expires_in { get; set; }

    [JsonPropertyName("scope")]
    public string? scope { get; set; }

    [JsonPropertyName("refresh_token")]
    public string? refresh_token { get; set; }
}
