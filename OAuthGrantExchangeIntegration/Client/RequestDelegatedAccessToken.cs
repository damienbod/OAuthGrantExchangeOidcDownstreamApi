using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace OAuthGrantExchangeIntegration.Client;

public static class RequestDelegatedAccessToken
{
    public static async Task<OauthTokenExchangeSuccessResponse?> GetDelegatedApiTokenObo(
        GetDelegatedApiTokenOboModel reqData, ILogger logger)
    {
        if (reqData.OboHttpClient == null)
            throw new ArgumentException("Httpclient missing, is null");

        // Content-Type: application/x-www-form-urlencoded
        var oboTokenExchangeBody = new[]
        {
            new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            new KeyValuePair<string, string>("client_id", reqData.ClientId),
            new KeyValuePair<string, string>("client_secret", OauthTokenExchangeExtentions.ToSha256(reqData.ClientSecret)),
            new KeyValuePair<string, string>("assertion", reqData.AccessToken),
            new KeyValuePair<string, string>("scope", reqData.Scope),
            new KeyValuePair<string, string>("requested_token_use", "on_behalf_of"),
        };

        var response = await reqData.OboHttpClient.PostAsync(reqData.EndpointUrl, new FormUrlEncodedContent(oboTokenExchangeBody));

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

            if(errorResult != null)
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
}
