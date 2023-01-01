using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace OAuthGrantExchangeIntegration.Client;

public static class RequestDelegatedAccessToken
{
    public static async Task<OauthTokenExchangeSuccessResponse?> GetDelegatedApiTokenTokenExchange(
        GetDelegatedApiTokenOAuthTokenExchangeModel reqData, ILogger logger)
    {
        if (reqData.GrantExchangeHttpClient == null)
            throw new ArgumentException("Httpclient missing, is null");

        string credentials = CreateBasicAuthenticationHeader(reqData);

        reqData.GrantExchangeHttpClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Basic", credentials);

        KeyValuePair<string, string>[] oauthTokenExchangeBody = CreateTokenExchangeBody(reqData);

        var response = await reqData.GrantExchangeHttpClient.PostAsync(reqData.EndpointUrl,
            new FormUrlEncodedContent(oauthTokenExchangeBody));

        if (response.IsSuccessStatusCode)
        {
            var tokenResponse = await JsonSerializer.DeserializeAsync<OauthTokenExchangeSuccessResponse>(
            await response.Content.ReadAsStreamAsync());
            return tokenResponse;
        }

        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            // Unauthorized error
            var errorResult = await JsonSerializer.DeserializeAsync<OauthTokenExchangeErrorResponse>(
           await response.Content.ReadAsStreamAsync());

            if (errorResult != null)
            {
                logger.LogInformation("{error} {error_description} {correlation_id} {trace_id}",
                    errorResult.error,
                    errorResult.error_description,
                    errorResult.correlation_id,
                    errorResult.trace_id);
            }
            else
            {
                logger.LogInformation("RequestDelegatedAccessToken Error, Unauthorized unknown reason");
            }
        }
        else
        {
            // unknown error, log
            logger.LogInformation("RequestDelegatedAccessToken Error unknown reason");
        }

        return null;
    }

    private static KeyValuePair<string, string>[] CreateTokenExchangeBody(GetDelegatedApiTokenOAuthTokenExchangeModel reqData)
    {
        // Content-Type: application/x-www-form-urlencoded
        var oauthTokenExchangeBody = new[]
        {
            new KeyValuePair<string, string>(OAuthGrantExchangeConsts.REQUEST_GRANT_TYPE, OAuthGrantExchangeConsts.GRANT_TYPE),
            new KeyValuePair<string, string>(OAuthGrantExchangeConsts.REQUEST_AUDIENCE, reqData.Audience),
            new KeyValuePair<string, string>(OAuthGrantExchangeConsts.REQUEST_SUBJECT_TOKEN_TYPE, OAuthGrantExchangeConsts.TOKEN_TYPE_ACCESS_TOKEN),
            new KeyValuePair<string, string>(OAuthGrantExchangeConsts.REQUEST_SUBJECT_TOKEN, reqData.AccessToken),
            new KeyValuePair<string, string>(OAuthGrantExchangeConsts.SCOPE, reqData.Scope)

            // new KeyValuePair<string, string>("resource", "--optional--")
            // new KeyValuePair<string, string>("requested_token_type", "--optional--")
            // new KeyValuePair<string, string>("actor_token", "--optional--")
            // new KeyValuePair<string, string>("actor_token_type", "--optional--")
        };

        return oauthTokenExchangeBody;
    }

    private static string CreateBasicAuthenticationHeader(GetDelegatedApiTokenOAuthTokenExchangeModel reqData)
    {
        var builder = new StringBuilder()
            .Append(reqData.ClientId)
            .Append(':')
            .Append(OauthTokenExchangeExtentions.ToSha256(reqData.ClientSecret));

        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(builder.ToString()));

        return credentials;
    }
}
