using System.Text.Json.Serialization;

namespace OAuthGrantExchangeIntegration;

/// <summary>
/// https://www.rfc-editor.org/rfc/rfc6749#section-5.2
/// </summary>
public class OauthTokenExchangeErrorResponse
{
    [JsonPropertyName("invalid_request")]
    public string invalid_request { get; set; } = string.Empty;
    [JsonPropertyName("invalid_client")]
    public string invalid_client { get; set; } = string.Empty;
    [JsonPropertyName("invalid_grant")]
    public string invalid_grant { get; set; } = string.Empty;
    [JsonPropertyName("unauthorized_client")]
    public string unauthorized_client { get; set; } = string.Empty;
    [JsonPropertyName("unsupported_grant_type")]
    public string unsupported_grant_type { get; set; } = string.Empty;

    [JsonPropertyName("error")]
    public string? error { get; set; }
    [JsonPropertyName("error_description")]
    public string? error_description { get; set; }
    [JsonPropertyName("error_codes")]
    public List<int>? error_codes { get; set; } = new List<int>();
    [JsonPropertyName("timestamp")]
    public DateTime? timestamp { get; set; }
    [JsonPropertyName("trace_id")]
    public string? trace_id { get; set; }
    [JsonPropertyName("correlation_id")]
    public string? correlation_id { get; set; }
    // json format "{\"access_token\":{\"polids\":{\"essential\":true,\"values\":[\"9ab03e19-ed42-4168-b6b7-7001fb3e933a\"]}}}"
    [JsonPropertyName("claims")]
    public string? claims { get; set; }
}

