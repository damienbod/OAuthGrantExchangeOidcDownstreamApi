using System.Text.Json.Serialization;

namespace OAuthGrantExchangeIntegration;

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc8693
/// </summary>
public class OauthTokenExchangePayload
{
    [JsonPropertyName(OAuthGrantExchangeConsts.REQUEST_GRANT_TYPE)]
    public string grant_type {get;set;} = string.Empty;

    [JsonPropertyName(OAuthGrantExchangeConsts.REQUEST_RESOURCE)]
    public string? resource { get; set; }

    [JsonPropertyName(OAuthGrantExchangeConsts.REQUEST_AUDIENCE)]
    public string? audience { get; set; }

    [JsonPropertyName(OAuthGrantExchangeConsts.SCOPE)]
    public string? scope { get; set; }

    [JsonPropertyName(OAuthGrantExchangeConsts.REQUEST_REQUESTED_TOKEN_TYPE)]
    public string? requested_token_type { get; set; }

    [JsonPropertyName(OAuthGrantExchangeConsts.REQUEST_SUBJECT_TOKEN)]
    public string subject_token { get; set; } = string.Empty;

    /// <summary>
    /// urn:ietf:params:oauth:token-type:access_token
    /// urn:ietf:params:oauth:token-type:refresh_token
    /// urn:ietf:params:oauth:token-type:id_token
    /// urn:ietf:params:oauth:token-type:saml1
    /// urn:ietf:params:oauth:token-type:saml2
    /// </summary>
    [JsonPropertyName(OAuthGrantExchangeConsts.REQUEST_SUBJECT_TOKEN_TYPE)]
    public string subject_token_type { get; set; } = string.Empty;

    [JsonPropertyName(OAuthGrantExchangeConsts.REQUEST_ACTOR_TOKEN)]
    public string? actor_token { get; set; }

    [JsonPropertyName(OAuthGrantExchangeConsts.REQUEST_ACTOR_TOKEN_TYPE)]
    public string actor_token_type { get; set; } = string.Empty;
}
