using System.Text.Json.Serialization;

namespace OAuthGrantExchangeIntegration;

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc8693
/// </summary>
public class OauthTokenExchangePayload
{
    [JsonPropertyName("grant_type")]
    public string grant_type {get;set;} = string.Empty;

    [JsonPropertyName("resource")]
    public string? resource { get; set; }

    [JsonPropertyName("audience")]
    public string? audience { get; set; }

    [JsonPropertyName("scope")]
    public string? scope { get; set; }

    [JsonPropertyName("requested_token_type")]
    public string? requested_token_type { get; set; }

    [JsonPropertyName("subject_token")]
    public string subject_token { get; set; } = string.Empty;

    [JsonPropertyName("subject_token_type")]
    public string subject_token_type { get; set; } = string.Empty;

    [JsonPropertyName("actor_token")]
    public string? actor_token { get; set; }

    [JsonPropertyName("actor_token_type")]
    public string actor_token_type { get; set; } = string.Empty;
}
