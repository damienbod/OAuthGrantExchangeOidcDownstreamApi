using Microsoft.AspNetCore.Authorization;

namespace DownstreamOpenIddictWebApi;

public class OpenIddictHandler : AuthorizationHandler<ApiRequirement>
{
    public const string MY_OPENIDDICT_ISS = "https://localhost:44318/";

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
        ApiRequirement requirement)
    {
        var issuer = string.Empty;

        var issClaim = context.User.Claims.FirstOrDefault(c => c.Type == "iss");
        if (issClaim != null)
            issuer = issClaim.Value;

        if (issuer == MY_OPENIDDICT_ISS) // OpenIddict
        {
            var scopeClaim = context.User.Claims.FirstOrDefault(c => c.Type == "scope"
                && c.Value == "dataEventRecords");
            if (scopeClaim != null)
            {
                // scope": "dataEventRecords",
                context.Succeed(requirement);
            }
        }

        return Task.CompletedTask;
    }
}
