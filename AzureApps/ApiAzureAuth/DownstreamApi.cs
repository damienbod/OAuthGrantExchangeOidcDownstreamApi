namespace ApiAzureAuth;

public class DownstreamApi
{
    public string IdentityProviderUrl { get; set; } = string.Empty;
    public string ApiBaseAddress { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string ScopeForAccessToken { get; set; } = string.Empty;

}
