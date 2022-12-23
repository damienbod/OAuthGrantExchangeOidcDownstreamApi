using IdentityModel.Client;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace ApiAzureAuth;

public class ApiService
{
    private readonly IOptions<DownstreamApi> _downstreamApi;
    private readonly IHttpClientFactory _clientFactory;
    private readonly ApiTokenCacheClient _apiTokenClient;

    public ApiService(
        IOptions<DownstreamApi> downstreamApi, 
        IHttpClientFactory clientFactory,
        ApiTokenCacheClient apiTokenClient)
    {
        _downstreamApi = downstreamApi;
        _clientFactory = clientFactory;
        _apiTokenClient = apiTokenClient;
    }

    public async Task<List<string>> GetApiDataAsync(string aadAccessToken)
    {
        try
        {
            var client = _clientFactory.CreateClient();

            client.BaseAddress = new Uri(_downstreamApi.Value.ApiBaseAddress);

            var access_token = await _apiTokenClient.GetApiTokenObo(
                _downstreamApi.Value.ClientId,
                _downstreamApi.Value.ScopeForAccessToken,
                _downstreamApi.Value.ClientSecret,
                aadAccessToken
            );

            client.SetBearerToken(access_token);

            var response = await client.GetAsync("api/values");
            if (response.IsSuccessStatusCode)
            {
                var data = await JsonSerializer.DeserializeAsync<List<string>>(
                await response.Content.ReadAsStreamAsync());

                if(data != null)
                    return data;

                return new List<string>();
            }

            throw new ApplicationException($"Status code: {response.StatusCode}, Error: {response.ReasonPhrase}");
        }
        catch (Exception e)
        {
            throw new ApplicationException($"Exception {e}");
        }
    }
}