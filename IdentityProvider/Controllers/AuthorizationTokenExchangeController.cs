using idunno.Authentication.Basic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OAuthGrantExchangeIntegration;
using OAuthGrantExchangeIntegration.Server;
using OpeniddictServer;
using OpeniddictServer.Data;
using System.Security.Claims;

namespace IdentityProvider.Controllers;

public class AuthorizationTokenExchangeController : Controller
{
    private readonly IWebHostEnvironment _environment;
    private readonly IConfiguration _configuration;
    private readonly OauthTokenExchangeConfiguration _oauthTokenExchangeConfiguration;
    private readonly ILogger<AuthorizationTokenExchangeController> _logger;
    private readonly UserManager<ApplicationUser> _userManager;

    public AuthorizationTokenExchangeController(IConfiguration configuration,
        IWebHostEnvironment env,
        IOptions<OauthTokenExchangeConfiguration> oauthTokenExchangeConfiguration,
        UserManager<ApplicationUser> userManager,
        ILoggerFactory loggerFactory)
    {
        _configuration = configuration;
        _environment = env;
        _oauthTokenExchangeConfiguration = oauthTokenExchangeConfiguration.Value;
        _userManager = userManager;
        _logger = loggerFactory.CreateLogger<AuthorizationTokenExchangeController>();
    }

    [Authorize(AuthenticationSchemes = BasicAuthenticationDefaults.AuthenticationScheme)]
    [HttpPost("~/connect/oauthTokenExchangetoken"), Produces("application/json")]
    public async Task<IActionResult> Exchange([FromForm] OauthTokenExchangePayload oauthTokenExchangePayload)
    {
        var (Valid, Reason, Error) = ValidateOauthTokenExchangeRequestPayload
            .IsValid(oauthTokenExchangePayload, _oauthTokenExchangeConfiguration);

        if (!Valid)
        {
            return UnauthorizedValidationParametersFailed(oauthTokenExchangePayload, Reason, Error);
        }

        // get well known endpoints and validate access token sent in the assertion
        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            _oauthTokenExchangeConfiguration.AccessTokenMetadataAddress,
            new OpenIdConnectConfigurationRetriever());

        var wellKnownEndpoints = await configurationManager.GetConfigurationAsync();

        var accessTokenValidationResult = await ValidateOauthTokenExchangeRequestPayload.ValidateTokenAndSignature(
            oauthTokenExchangePayload.subject_token,
            _oauthTokenExchangeConfiguration,
            wellKnownEndpoints.SigningKeys);

        if (!accessTokenValidationResult.Valid)
        {
            return UnauthorizedValidationTokenAndSignatureFailed(oauthTokenExchangePayload, accessTokenValidationResult);
        }

        // get claims from Microsoft Entra ID token and re use in OpenIddict token
        var claimsIdentity = accessTokenValidationResult.ClaimsIdentity;

        var isDelegatedToken = ValidateOauthTokenExchangeRequestPayload.IsDelegatedAadAccessToken(claimsIdentity);

        if (!isDelegatedToken)
        {
            return UnauthorizedValidationRequireDelegatedTokenFailed();
        }

        var name = ValidateOauthTokenExchangeRequestPayload.GetPreferredUserName(claimsIdentity);
        var isNameAndEmail = ValidateOauthTokenExchangeRequestPayload.IsEmailValid(name);
        if (!isNameAndEmail)
        {
            return UnauthorizedValidationPreferredUserNameFailed();
        }

        // validate user exists
        // Note the email can change and the OID should be used for this check.
        var user = await _userManager.FindByNameAsync(name);
        if (user == null)
        {
            return UnauthorizedValidationNoUserExistsFailed();
        }

        // use data and return new access token
        var (ActiveCertificate, _) = await StartupExtensions.GetCertificates(_environment, _configuration);

        var tokenData = new CreateDelegatedAccessTokenPayloadModel
        {
            Sub = Guid.NewGuid().ToString(),
            ClaimsIdentity = claimsIdentity,
            SigningCredentials = ActiveCertificate,
            Scope = _oauthTokenExchangeConfiguration.ScopeForNewAccessToken,
            Audience = _oauthTokenExchangeConfiguration.AudienceForNewAccessToken,
            Issuer = _oauthTokenExchangeConfiguration.IssuerForNewAccessToken,
            OriginalClientId = _oauthTokenExchangeConfiguration.AccessTokenAudience
        };

        var accessToken = CreateDelegatedAccessTokenPayload.GenerateJwtTokenAsync(tokenData);

        _logger.LogInformation("OAuth token exchange new access token returned sub {sub}", tokenData.Sub);

        if (IdentityModelEventSource.ShowPII)
        {
            _logger.LogDebug("OAuth token exchange new access token returned for sub {sub} for user {Username}", tokenData.Sub,
                ValidateOauthTokenExchangeRequestPayload.GetPreferredUserName(claimsIdentity));
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

    private IActionResult UnauthorizedValidationRequireDelegatedTokenFailed()
    {
        var errorResult = new OauthTokenExchangeErrorResponse
        {
            error = OAuthGrantExchangeConsts.ERROR_INVALID_REQUEST,
            error_description = "Only delegated access tokens accepted",
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

    private IActionResult UnauthorizedValidationPreferredUserNameFailed()
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

    private IActionResult UnauthorizedValidationTokenAndSignatureFailed(OauthTokenExchangePayload oauthTokenExchangePayload, (bool Valid, string Reason, ClaimsIdentity ClaimsIdentity) accessTokenValidationResult)
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
            _logger.LogDebug("OAuth token exchange new access token returned for assertion {assertion}", oauthTokenExchangePayload.subject_token);
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
            _logger.LogDebug("OAuth token exchange new access token returned for assertion {assertion}", oauthTokenExchangePayload.subject_token);
        }

        return Unauthorized(errorResult);
    }
}
