using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.Resource;
using Microsoft.Net.Http.Headers;

namespace ApiAzureAuth.Controllers
{
    [Authorize]
    [AuthorizeForScopes(Scopes = new string[] { "api://72286b8d-5010-4632-9cea-e69e565a5517/user_impersonation" })]
    [ApiController]
    [Route("[controller]")]
    public class MyApiController : ControllerBase
    {
        private readonly ApiService _apiService;

        public MyApiController(ApiService apiService)
        {
            _apiService = apiService;
        }

        [HttpGet]
        public async Task<IEnumerable<string>?> Get()
        {
            var scopeRequiredByApi = new string[] { "access_as_user" };
            HttpContext.VerifyUserHasAnyAcceptedScope(scopeRequiredByApi);

            var aadBearerToken = Request.Headers[HeaderNames.Authorization]
                .ToString().Replace("Bearer ", "");

            var dataFromDownstreamApi = await _apiService.GetApiDataAsync(aadBearerToken);
            return dataFromDownstreamApi;
        }
    }
}
