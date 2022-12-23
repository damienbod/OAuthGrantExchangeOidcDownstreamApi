namespace OAuthGrantExchangeIntegration.Client;

public class GetDelegatedApiTokenOboModel
{
    public HttpClient? OboHttpClient { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string EndpointUrl { get; set; } = string.Empty;
    public string AccessToken { get; set; } = string.Empty;
}
