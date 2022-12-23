using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using OAuthGrantExchangeIntegration;
using OAuthGrantExchangeIntegration.Server;
using OpeniddictServer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using OpeniddictServer.Data;
using Microsoft.AspNetCore.Authorization;

namespace IdentityProvider.Controllers;

public class AuthorizationTokenExchangeController : Controller
{
    private readonly IWebHostEnvironment _environment;
    private readonly IConfiguration _configuration;
    private readonly OauthTokenExchangeConfiguration _oauthTokenExchangeConfigurationConfiguration;
    private readonly ILogger<AuthorizationTokenExchangeController> _logger;
    private readonly UserManager<ApplicationUser> _userManager;

    public AuthorizationTokenExchangeController(IConfiguration configuration, 
        IWebHostEnvironment env, IOptions<OauthTokenExchangeConfiguration> oauthTokenExchangeConfigurationConfiguration,
        UserManager<ApplicationUser> userManager,
        ILoggerFactory loggerFactory)
    {
        _configuration = configuration;
        _environment = env;
        _oauthTokenExchangeConfigurationConfiguration = oauthTokenExchangeConfigurationConfiguration.Value;
        _userManager= userManager;
        _logger = loggerFactory.CreateLogger<AuthorizationTokenExchangeController>();
    }

    // TODO require auth with Authorization Basic clientid:clientSecret
    [AllowAnonymous]
    [HttpPost("~/connect/oauthTokenExchangetoken"), Produces("application/json")]
    public async Task<IActionResult> Exchange([FromForm] OauthTokenExchangePayload oauthTokenExchangePayload)
    {
        var (Valid, Reason, Error) = ValidateOauthTokenExchangeRequestPayload
            .IsValid(oauthTokenExchangePayload, _oauthTokenExchangeConfigurationConfiguration);

        if(!Valid)
        {
            return UnauthorizedValidationParametersFailed(oauthTokenExchangePayload, Reason, Error);
        }

        // get well known endpoints and validate access token sent in the assertion
        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            _oauthTokenExchangeConfigurationConfiguration.AccessTokenMetadataAddress, 
            new OpenIdConnectConfigurationRetriever());

        var wellKnownEndpoints =  await configurationManager.GetConfigurationAsync();

        var accessTokenValidationResult = ValidateOauthTokenExchangeRequestPayload.ValidateTokenAndSignature(
            oauthTokenExchangePayload.subject_token,
            _oauthTokenExchangeConfigurationConfiguration,
            wellKnownEndpoints.SigningKeys);
        
        if(!accessTokenValidationResult.Valid)
        {
            return UnauthorizedValidationTokenAndSignatureFailed(oauthTokenExchangePayload, accessTokenValidationResult);
        }

        // get claims from aad token and re use in OpenIddict token
        var claimsPrincipal = accessTokenValidationResult.ClaimsPrincipal;

        var name = ValidateOauthTokenExchangeRequestPayload.GetPreferredUserName(claimsPrincipal);
        var isNameAnEmail = ValidateOauthTokenExchangeRequestPayload.IsEmailValid(name);
        if(!isNameAnEmail)
        {
            return UnauthorizedValidationPrefferedUserNameFailed();
        }

        // validate user exists
        // TODO validate that Azure AD access token is a delegated token => must contain a scp claim and a oid claim

        var user = await _userManager.FindByNameAsync(name);
        if (user == null)
        {
            return UnauthorizedValidationNoUserExistsFailed();
        }

        // use data and return new access token
        var (ActiveCertificate, _) = await Startup.GetCertificates(_environment, _configuration);

        var tokenData = new CreateDelegatedAccessTokenPayloadModel
        {
            Sub = Guid.NewGuid().ToString(),
            ClaimsPrincipal = claimsPrincipal,
            SigningCredentials = ActiveCertificate,
            Scope = _oauthTokenExchangeConfigurationConfiguration.ScopeForNewAccessToken,
            Audience = _oauthTokenExchangeConfigurationConfiguration.AudienceForNewAccessToken,
            Issuer = _oauthTokenExchangeConfigurationConfiguration.IssuerForNewAccessToken,
            OriginalClientId = _oauthTokenExchangeConfigurationConfiguration.AccessTokenAudience
        };

        var accessToken = CreateDelegatedAccessTokenPayload.GenerateJwtTokenAsync(tokenData);

        _logger.LogInformation("OBO new access token returned sub {sub}", tokenData.Sub);

        if(IdentityModelEventSource.ShowPII)
        {
            _logger.LogDebug("OBO new access token returned for sub {sub} for user {Username}", tokenData.Sub,
                ValidateOauthTokenExchangeRequestPayload.GetPreferredUserName(claimsPrincipal));
        }

        return Ok(new OauthTokenExchangeSuccessResponse
        {
            expires_in = 60 * 60,
            access_token = accessToken,
            scope = oauthTokenExchangePayload.scope
        });
    }

    private IActionResult UnauthorizedValidationNoUserExistsFailed()
    {
        var errorResult = new OauthTokenExchangeErrorResponse
        {
            error = OAuthGrantExchangeConsts.ERROR_INVALID_REQUEST,
            error_description = "user does not exist",
            timestamp = DateTime.UtcNow,
            correlation_id = Guid.NewGuid().ToString(),
            trace_id = Guid.NewGuid().ToString(),
        };

        _logger.LogInformation("{error} {error_description} {correlation_id} {trace_id}",
            errorResult.error,
            errorResult.error_description,
            errorResult.correlation_id,
            errorResult.trace_id);

        return Unauthorized(errorResult);
    }

    private IActionResult UnauthorizedValidationPrefferedUserNameFailed()
    {
        var errorResult = new OauthTokenExchangeErrorResponse
        {
            error = OAuthGrantExchangeConsts.ERROR_INVALID_REQUEST,
            error_description = "incorrect email used in preferred user name",
            timestamp = DateTime.UtcNow,
            correlation_id = Guid.NewGuid().ToString(),
            trace_id = Guid.NewGuid().ToString(),
        };

        _logger.LogInformation("{error} {error_description} {correlation_id} {trace_id}",
            errorResult.error,
            errorResult.error_description,
            errorResult.correlation_id,
            errorResult.trace_id);

        return Unauthorized(errorResult);
    }

    private IActionResult UnauthorizedValidationTokenAndSignatureFailed(OauthTokenExchangePayload oauthTokenExchangePayload, (bool Valid, string Reason, ClaimsPrincipal ClaimsPrincipal) accessTokenValidationResult)
    {
        var errorResult = new OauthTokenExchangeErrorResponse
        {
            error = OAuthGrantExchangeConsts.ERROR_INVALID_REQUEST,
            error_description = accessTokenValidationResult.Reason,
            timestamp = DateTime.UtcNow,
            correlation_id = Guid.NewGuid().ToString(),
            trace_id = Guid.NewGuid().ToString(),
        };

        if (IdentityModelEventSource.ShowPII)
        {
            _logger.LogDebug("OBO new access token returned for assertion {assertion}", oauthTokenExchangePayload.subject_token);
        }

        _logger.LogInformation("{error} {error_description} {correlation_id} {trace_id}",
            errorResult.error,
            errorResult.error_description,
            errorResult.correlation_id,
            errorResult.trace_id);

        return Unauthorized(errorResult);
    }

    private IActionResult UnauthorizedValidationParametersFailed(OauthTokenExchangePayload oauthTokenExchangePayload, 
        string Reason, string error)
    {
        var errorResult = new OauthTokenExchangeErrorResponse
        {
            error = error,
            error_description = Reason,
            timestamp = DateTime.UtcNow,
            correlation_id = Guid.NewGuid().ToString(),
            trace_id = Guid.NewGuid().ToString(),
        };

        _logger.LogInformation("{error} {error_description} {correlation_id} {trace_id}",
            errorResult.error,
            errorResult.error_description,
            errorResult.correlation_id,
            errorResult.trace_id);

        if (IdentityModelEventSource.ShowPII)
        {
            _logger.LogDebug("OBO new access token returned for assertion {assertion}", oauthTokenExchangePayload.subject_token);
        }

        return Unauthorized(errorResult);
    }
}
