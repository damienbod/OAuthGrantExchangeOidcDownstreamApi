using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mail;
using System.Security.Claims;

namespace OAuthGrantExchangeIntegration.Server;

public static class ValidateOauthTokenExchangeRequestPayload
{
    public static (bool Valid, string Reason) IsValid(OauthTokenExchangePayload oauthTokenExchangePayload, OauthTokenExchangeConfiguration oauthTokenExchangeConfiguration)
    {
        if(!oauthTokenExchangePayload.grant_type.Equals(OAuthGrantExchangeConsts.GRANT_TYPE))
        {
            return (false, $"grant_type parameter has an incorrect value, expected {OAuthGrantExchangeConsts.GRANT_TYPE}");
        };

        if (!oauthTokenExchangePayload.subject_token_type.ToLower().Equals(OAuthGrantExchangeConsts.TOKEN_TYPE_ACCESS_TOKEN))
        {
            return (false, $"subject_token_type parameter has an incorrect value, expected {OAuthGrantExchangeConsts.TOKEN_TYPE_ACCESS_TOKEN}");
        };

        if (!oauthTokenExchangePayload.client_id.Equals(oauthTokenExchangeConfiguration.ClientId))
        {
            return (false, "obo client_id parameter has an incorrect value");
        };

        if (!oauthTokenExchangePayload.scope.ToLower().Equals(oauthTokenExchangeConfiguration.ScopeForNewAccessToken.ToLower()))
        {
            return (false, "scope parameter has an incorrect value");
        };

        return (true, string.Empty);
    }

    public static (bool Valid, string Reason, ClaimsPrincipal? ClaimsPrincipal) ValidateTokenAndSignature(
        string jwtToken, 
        OauthTokenExchangeConfiguration oboConfiguration, 
        ICollection<SecurityKey> signingKeys)
    {
        try
        {
            var validationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(1),
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidateIssuer = true,
                ValidIssuer = oboConfiguration.AccessTokenAuthority,
                ValidateAudience = true, 
                ValidAudience = oboConfiguration.AccessTokenAudience
            };

            ISecurityTokenValidator tokenValidator = new JwtSecurityTokenHandler();

            var claimsPrincipal = tokenValidator.ValidateToken(jwtToken, validationParameters, out var _);

            return (true, string.Empty, claimsPrincipal);
        }
        catch (Exception ex)
        {
            return (false, $"Access Token Authorization failed {ex.Message}", null);
        }
    }

    public static string GetPreferredUserName(ClaimsPrincipal claimsPrincipal)
    {
        string preferredUsername = string.Empty;
        var preferred_username = claimsPrincipal.Claims.FirstOrDefault(t => t.Type == "preferred_username");
        if (preferred_username != null)
        {
            preferredUsername = preferred_username.Value;
        }

        return preferredUsername;
    }

    public static string GetAzpacr(ClaimsPrincipal claimsPrincipal)
    {
        string azpacr = string.Empty;
        var azpacrClaim = claimsPrincipal.Claims.FirstOrDefault(t => t.Type == "azpacr");
        if (azpacrClaim != null)
        {
            azpacr = azpacrClaim.Value;
        }

        return azpacr;
    }

    public static string GetAzp(ClaimsPrincipal claimsPrincipal)
    {
        string azp = string.Empty;
        var azpClaim = claimsPrincipal.Claims.FirstOrDefault(t => t.Type == "azp");
        if (azpClaim != null)
        {
            azp = azpClaim.Value;
        }

        return azp;
    }

    public static bool IsEmailValid(string email)
    {
        if (!MailAddress.TryCreate(email, out var mailAddress))
            return false;

        // And if you want to be more strict:
        var hostParts = mailAddress.Host.Split('.');
        if (hostParts.Length == 1)
            return false; // No dot.
        if (hostParts.Any(p => p == string.Empty))
            return false; // Double dot.
        if (hostParts[^1].Length < 2)
            return false; // TLD only one letter.

        if (mailAddress.User.Contains(' '))
            return false;
        if (mailAddress.User.Split('.').Any(p => p == string.Empty))
            return false; // Double dot or dot at end of user part.

        return true;
    }
}
