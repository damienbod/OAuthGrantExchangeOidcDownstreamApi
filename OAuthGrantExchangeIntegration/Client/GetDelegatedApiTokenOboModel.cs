namespace OAuthGrantExchangeIntegration.Client;

public class GetDelegatedApiTokenOboModel
{
    public HttpClient? GrantExchangeHttpClient { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;

    // Add to header Authorization Basic
    public string ClientSecret { get; set; } = string.Empty;
    public string EndpointUrl { get; set; } = string.Empty;
    public string AccessToken { get; set; } = string.Empty;
}
