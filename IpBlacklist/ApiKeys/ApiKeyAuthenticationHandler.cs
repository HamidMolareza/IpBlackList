using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace IpBlacklist.ApiKeys;

public class ApiKeyAuthenticationHandler(
    IOptionsMonitor<ApiKeyAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IApiKeyValidator apiKeyValidator)
    : AuthenticationHandler<ApiKeyAuthenticationOptions>(options, logger, encoder) {
    protected override Task<AuthenticateResult> HandleAuthenticateAsync() {
        // Check for the API key in the header
        if (!Request.Headers.TryGetValue("X-API-KEY", out var apiKeyValues)) {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var apiKey = apiKeyValidator.TryParse(apiKeyValues.FirstOrDefault());
        if (apiKey is null) {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        // Validate the API key
        if (!apiKeyValidator.IsValid(apiKey)) {
            return Task.FromResult(AuthenticateResult.Fail("Invalid API key"));
        }

        // Create a claims identity for the authenticated user
        var claims = new[] {
            new Claim(ClaimTypes.Name, "ApiKeyUser"),
            new Claim(ApiKeyClaims.ApiKeyClientId, apiKey.ClientId)
            
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);


        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}

public class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions {
    // No additional options needed for now
}