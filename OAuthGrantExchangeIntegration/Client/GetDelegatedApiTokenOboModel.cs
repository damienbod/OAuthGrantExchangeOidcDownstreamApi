namespace OAuthGrantExchangeIntegration.Client;

public class GetDelegatedApiTokenOAuthTokenExchangeModel
{
    public HttpClient? GrantExchangeHttpClient { get; set; }

    /// <summary>
    /// This is the client_id in Entra ID
    /// </summary>
    public string Audience { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;

    /// <summary>
    /// Add to header Authorization Basic
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;

    public string EndpointUrl { get; set; } = string.Empty;
    public string AccessToken { get; set; } = string.Empty;
}
