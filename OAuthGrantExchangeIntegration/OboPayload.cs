using System.Text.Json.Serialization;

namespace OAuthGrantExchangeIntegration;

public class OboPayload
{
    [JsonPropertyName("grant_type")]
    public string grant_type {get;set;} = string.Empty;

    [JsonPropertyName("client_id")]
    public string client_id { get; set; } = string.Empty;

    [JsonPropertyName("client_secret")]
    public string client_secret { get; set; } = string.Empty;

    [JsonPropertyName("assertion")]
    public string assertion { get; set; } = string.Empty;

    [JsonPropertyName("scope")]
    public string scope { get; set; } = string.Empty;

    [JsonPropertyName("requested_token_use")]
    public string requested_token_use { get; set; } = string.Empty;
}
