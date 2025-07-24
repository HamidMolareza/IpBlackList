using IpBlacklist.ApiKeys;
using IpBlacklist.Data;
using IpBlacklist.Data.Interceptors;
using IpBlacklist.Data.Models;
using IpBlacklist.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, services, configuration) => {
    configuration
        .ReadFrom.Configuration(context.Configuration) // Reads from appsettings.json
        .ReadFrom.Services(services) // Enables DI-injected enrichers
        .Enrich.FromLogContext()
        .Enrich.WithEnvironmentName()
        .Enrich.WithMachineName();
});

// Add services to the container.
builder.Services.AddSingleton<SaveChangesInterceptor, CreatedInterceptor>();
builder.Services.AddSingleton<SaveChangesInterceptor, SoftDeleteInterceptor>();

var connectionString = builder.Configuration.GetConnectionString("Default");
builder.Services.AddDbContext<AppDbContext>((sp, options) => {
    options.UseSqlServer(connectionString);
    options.AddInterceptors(sp.GetServices<SaveChangesInterceptor>());
});

builder.Services.Configure<ApiKeyOptions>(builder.Configuration.GetSection(ApiKeyOptions.OptionName));
builder.Services.AddSingleton<IApiKeyValidator, ApiKeyValidator>();
builder.Services.AddHttpContextAccessor();

builder.Services.AddAuthentication("ApiKeyScheme")
    .AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>("ApiKeyScheme", null);

// Add authorization with the API key policy
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("ApiKeyPolicy", policy => {
        policy.AddAuthenticationSchemes("ApiKeyScheme");
        policy.RequireAuthenticatedUser();
    });


builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

app.UseSerilogRequestLogging(options => {
    options.EnrichDiagnosticContext = (diagnosticContext, httpContext) => {
        // Still enrich DiagnosticContext for structured log sinks
        diagnosticContext.Set("RequestIp", httpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty);

        var clientIp = httpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        diagnosticContext.Set("ClientIp", clientIp);

        var clientId = httpContext.User.FindFirst(ApiKeyClaims.ApiKeyClientId)?.Value ?? "Unknown";
        diagnosticContext.Set("ClientId", clientId);
    };

    options.MessageTemplate =
        "HTTP {RequestMethod} responded {StatusCode} in {Elapsed:0.0000} ms";
});


using (var scope = app.Services.CreateScope()) {
    var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await dbContext.Database.EnsureCreatedAsync();
    await dbContext.Database.MigrateAsync();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment()) {
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/blacklist", async (
    BlacklistEntryRequest dto,
    AppDbContext db,
    HttpRequest request,
    ILogger<Program> logger) => {
    var requesterIp = request.HttpContext.Connection.RemoteIpAddress?.ToString();

    logger.LogInformation("Request to block: {TargetIp}", dto.BlackIp);

    var entry = await db.BlacklistEntries.FirstOrDefaultAsync(e => e.BlackIp == dto.BlackIp);
    if (entry is not null) return Results.Ok();

    var clientId = request.HttpContext.User.FindFirst(ApiKeyClaims.ApiKeyClientId)?.Value;
    var newEntry = new BlacklistEntry {
        BlackIp = dto.BlackIp,
        RequesterIp = requesterIp,
        RegisteredByClient = clientId
    };
    db.BlacklistEntries.Add(newEntry);

    await db.SaveChangesAsync();
    return Results.Created($"/blacklist/{newEntry.Id}", BlacklistEntryResponse.MapFrom(newEntry));
}).RequireAuthorization("ApiKeyPolicy");


app.MapGet("/blacklist/{id:int}", async (int id, AppDbContext db) => {
    var entry = await db.BlacklistEntries.FirstOrDefaultAsync(e => e.Id == id);
    return entry is null ? Results.NotFound() : Results.Ok(BlacklistEntryResponse.MapFrom(entry));
}).RequireAuthorization("ApiKeyPolicy");

app.MapGet("/blacklist/{ip}", async (string ip, AppDbContext db) => {
    var entry = await db.BlacklistEntries.FirstOrDefaultAsync(e => e.BlackIp == ip);
    return entry is null ? Results.NotFound() : Results.Ok(BlacklistEntryResponse.MapFrom(entry));
}).RequireAuthorization("ApiKeyPolicy");

app.MapGet("/blacklist", async (AppDbContext db) => {
    var entries = await db.BlacklistEntries.ToListAsync();
    var response = entries.Select(BlacklistEntryResponse.MapFrom);
    return Results.Ok(response);
}).RequireAuthorization("ApiKeyPolicy");

app.Run();