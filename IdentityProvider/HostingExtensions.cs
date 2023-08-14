using Fido2Identity;
using Fido2NetLib;
using idunno.Authentication.Basic;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Logging;
using OAuthGrantExchangeIntegration.Server;
using OAuthGrantExchangeIntegration;
using OpeniddictServer.Data;
using Quartz;
using Serilog;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using StsServerIdentity.Services.Certificate;
using System.Security.Cryptography.X509Certificates;

namespace OpeniddictServer;

internal static class HostingExtensions
{
    private static IWebHostEnvironment? _env;
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        var services = builder.Services;
        var configuration = builder.Configuration;
        _env = builder.Environment;

        services.AddControllersWithViews();
        services.AddRazorPages();

        services.Configure<OauthTokenExchangeConfiguration>(configuration.GetSection("TokenExchangeConfiguration"));

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            // Configure the context to use Microsoft SQL Server.
            options.UseSqlite(configuration.GetConnectionString("DefaultConnection"));

            // Register the entity sets needed by OpenIddict.
            // Note: use the generic overload if you need
            // to replace the default OpenIddict entities.
            options.UseOpenIddict();
        });

        services.AddDatabaseDeveloperPageExceptionFilter();

        services.AddIdentity<ApplicationUser, IdentityRole>()
          .AddEntityFrameworkStores<ApplicationDbContext>()
          .AddDefaultTokenProviders()
          .AddDefaultUI()
          .AddTokenProvider<Fido2UserTwoFactorTokenProvider>("FIDO2");

        services.Configure<Fido2Configuration>(configuration.GetSection("fido2"));
        services.AddScoped<Fido2Store>();

        services.AddDistributedMemoryCache();

        services.AddSession(options =>
        {
            options.IdleTimeout = TimeSpan.FromMinutes(2);
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.None;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        });

        services.Configure<IdentityOptions>(options =>
        {
            // Configure Identity to use the same JWT claims as OpenIddict instead
            // of the legacy WS-Federation claims it uses by default (ClaimTypes),
            // which saves you from doing the mapping in your authorization controller.
            options.ClaimsIdentity.UserNameClaimType = Claims.Name;
            options.ClaimsIdentity.UserIdClaimType = Claims.Subject;
            options.ClaimsIdentity.RoleClaimType = Claims.Role;
            options.ClaimsIdentity.EmailClaimType = Claims.Email;

            // Note: to require account confirmation before login,
            // register an email sender service (IEmailSender) and
            // set options.SignIn.RequireConfirmedAccount to true.
            //
            // For more information, visit https://aka.ms/aspaccountconf.
            options.SignIn.RequireConfirmedAccount = false;
        });

        // OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
        // (like pruning orphaned authorizations/tokens from the database) at regular intervals.
        services.AddQuartz(options =>
        {
            options.UseMicrosoftDependencyInjectionJobFactory();
            options.UseSimpleTypeLoader();
            options.UseInMemoryStore();
        });

        services.AddCors(options =>
        {
            options.AddPolicy("AllowAllOrigins",
                builder =>
                {
                    builder
                        .AllowCredentials()
                        .WithOrigins(
                            "https://localhost:4200")
                        .SetIsOriginAllowedToAllowWildcardSubdomains()
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
        });

        // Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
        services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

        var (ActiveCertificate, SecondaryCertificate) = GetCertificates(_env, configuration)
            .GetAwaiter().GetResult();

        services.AddOpenIddict()

            // Register the OpenIddict core components.
            .AddCore(options =>
            {
                // Configure OpenIddict to use the Entity Framework Core stores and models.
                // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                options.UseEntityFrameworkCore()
                       .UseDbContext<ApplicationDbContext>();

                // Enable Quartz.NET integration.
                options.UseQuartz();
            })

            // Register the OpenIddict server components.
            .AddServer(options =>
            {
                // Enable the authorization, logout, token and userinfo endpoints.
                options.SetAuthorizationEndpointUris("connect/authorize")
                   //.SetDeviceEndpointUris("connect/device")
                   .SetIntrospectionEndpointUris("connect/introspect")
                   .SetLogoutEndpointUris("connect/logout")
                   .SetTokenEndpointUris("connect/token")
                   .SetUserinfoEndpointUris("connect/userinfo")
                   .SetVerificationEndpointUris("connect/verify");

                // Note: this sample uses the code, device code, password and refresh token flows, but you
                // can enable the other flows if you need to support implicit or client credentials.
                options.AllowAuthorizationCodeFlow()
                    .AllowCustomFlow(OAuthGrantExchangeConsts.GRANT_TYPE)
                    .AllowClientCredentialsFlow()
                    .AllowHybridFlow()
                    .AllowRefreshTokenFlow();

                // Mark the "email", "profile", "roles" and "dataEventRecords" scopes as supported scopes.
                options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, "dataEventRecords");

                // remove this with introspection, added security
                options.DisableAccessTokenEncryption();

                // Register the signing and encryption credentials.
                options.AddDevelopmentEncryptionCertificate()
                       .AddSigningCertificate(ActiveCertificate);

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableLogoutEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableUserinfoEndpointPassthrough()
                    .EnableStatusCodePagesIntegration();
            })

            // Register the OpenIddict validation components.
            .AddValidation(options =>
            {
                // Import the configuration from the local OpenIddict server instance.
                options.UseLocalServer();

                // Register the ASP.NET Core host.
                options.UseAspNetCore();
            });

        services.AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme)
            .AddBasic(options =>
            {
                options.Realm = "oauthtokenexchange";
                options.Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        var config = context.HttpContext.RequestServices.GetService<IOptions<OauthTokenExchangeConfiguration>>();

                        if (ValidateBasicAuthentication.IsValid(context.Username, context.Password, config.Value))
                        {
                            var claims = new[]
                            {
                                new Claim( ClaimTypes.NameIdentifier, context.Username, ClaimValueTypes.String, context.Options.ClaimsIssuer),
                                new Claim( ClaimTypes.Name, context.Username, ClaimValueTypes.String, context.Options.ClaimsIssuer)
                            };

                            context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                            context.Success();
                        }

                        return Task.CompletedTask;
                    }
                };
            });

        // Register the worker responsible of seeding the database.
        // Note: in a real world application, this step should be part of a setup script.
        services.AddHostedService<Worker>();

        return builder.Build();
    }
    
    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        IdentityModelEventSource.ShowPII = true;
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        app.UseSerilogRequestLogging();

        if (_env!.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseCors("AllowAllOrigins");

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseSession();

        app.MapControllers();
        app.MapDefaultControllerRoute();
        app.MapRazorPages();

        return app;
    }

    public static async Task<(X509Certificate2 ActiveCertificate, X509Certificate2 SecondaryCertificate)> GetCertificates(
       IWebHostEnvironment environment, IConfiguration configuration)
    {
        var certificateConfiguration = new CertificateConfiguration
        {
            // Use an Azure key vault
            CertificateNameKeyVault = configuration["CertificateNameKeyVault"], //"StsCert",
            KeyVaultEndpoint = configuration["AzureKeyVaultEndpoint"], // "https://damienbod.vault.azure.net"

            // Use a local store with thumbprint
            //UseLocalCertStore = Convert.ToBoolean(configuration["UseLocalCertStore"]),
            //CertificateThumbprint = configuration["CertificateThumbprint"],

            // development certificate
            DevelopmentCertificatePfx = Path.Combine(environment.ContentRootPath, "sts_dev_cert.pfx"),
            DevelopmentCertificatePassword = "1234" //configuration["DevelopmentCertificatePassword"] //"1234",
        };

        (X509Certificate2 ActiveCertificate, X509Certificate2 SecondaryCertificate) certs = await CertificateService.GetCertificates(
            certificateConfiguration).ConfigureAwait(false);

        return certs;
    }
}