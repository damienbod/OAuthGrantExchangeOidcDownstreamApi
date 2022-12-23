using System.Text.Json.Serialization;

namespace OAuthGrantExchangeIntegration;

public class OboErrorResponse
{
    [JsonPropertyName("error")]
    public string error { get; set; } = string.Empty;
    [JsonPropertyName("error_description")]
    public string error_description { get; set; } = string.Empty;
    [JsonPropertyName("error_codes")]
    public List<int> error_codes { get; set; } = new List<int>();
    [JsonPropertyName("timestamp")]
    public DateTime timestamp { get; set; }
    [JsonPropertyName("trace_id")]
    public string trace_id { get; set; } = string.Empty;
    [JsonPropertyName("correlation_id")]
    public string correlation_id { get; set; } = string.Empty;
    // json format "{\"access_token\":{\"polids\":{\"essential\":true,\"values\":[\"9ab03e19-ed42-4168-b6b7-7001fb3e933a\"]}}}"
    [JsonPropertyName("claims")]
    public string claims { get; set; } = string.Empty;
}

