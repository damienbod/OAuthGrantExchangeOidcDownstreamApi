namespace OAuthGrantExchangeIntegration.Server;

public static class ValidateBasicAuthentication
{
    public static bool IsValid(string clientId, string clientSecret, OauthTokenExchangeConfiguration oauthTokenExchangeConfiguration)
    {
        if (!clientId.Equals(oauthTokenExchangeConfiguration.ClientId))
        {
            return false;
        };

        if (!clientSecret.Equals(OauthTokenExchangeExtentions.ToSha256(oauthTokenExchangeConfiguration.ClientSecret)))
        {
            return false;
        };

        return true;
    }
}