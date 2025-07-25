using IpBlacklist.ApiKeys;
using IpBlacklist.Data;
using IpBlacklist.Data.Interceptors;
using IpBlacklist.Data.Models;
using IpBlacklist.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Serilog;
using Serilog.Context;
using System.Diagnostics;

var builder = WebApplication.CreateBuilder(args);

// Configure Serilog from appsettings.json only
builder.Host.UseSerilog((context, configuration) =>
    configuration.ReadFrom.Configuration(context.Configuration));

// Add services to the container
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

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("ApiKeyPolicy", policy => {
        policy.AddAuthenticationSchemes("ApiKeyScheme");
        policy.RequireAuthenticatedUser();
    });

builder.Services.AddControllers();
builder.Services.AddOpenApi();

var app = builder.Build();

// Custom middleware for request-scoped logging
app.Use(async (context, next) => {
    var requestId = Guid.NewGuid().ToString();
    var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
    var clientId = context.User.FindFirst(ApiKeyClaims.ApiKeyClientId)?.Value ?? "Unknown";

    using (LogContext.PushProperty("RequestId", requestId))
    using (LogContext.PushProperty("ClientIp", clientIp))
    using (LogContext.PushProperty("ClientId", clientId)) {
        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
        var stopwatch = Stopwatch.StartNew();

        logger.LogInformation("Starting request {RequestMethod} {RequestPath}",
            context.Request.Method, context.Request.Path);

        try {
            await next();
        }
        finally {
            stopwatch.Stop();
            logger.LogInformation("Completed request {RequestMethod} {RequestPath} with status {StatusCode} in {Elapsed:0.0000} ms",
                context.Request.Method, context.Request.Path, context.Response.StatusCode, stopwatch.Elapsed.TotalMilliseconds);
        }
    }
});

using (var scope = app.Services.CreateScope()) {
    var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    // await dbContext.Database.EnsureDeletedAsync();
    await dbContext.Database.EnsureCreatedAsync();
    await dbContext.Database.MigrateAsync();
}

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
    var clientId = request.HttpContext.User.FindFirst(ApiKeyClaims.ApiKeyClientId)?.Value;
    logger.LogInformation("{ClientId} request to block IP: {TargetIp}", clientId, dto.BlackIp);
    if (clientId is null) return Results.Unauthorized();

    var entry = await db.BlacklistEntries.AsTracking().FirstOrDefaultAsync(e => e.BlackIp == dto.BlackIp);
    if (entry is not null) {
        if (!entry.ClientExist(clientId)) {
            entry.AddClient(clientId);
            db.Entry(entry).State = EntityState.Modified;
            await db.SaveChangesAsync();
        }

        return Results.Ok();
    }

    var newEntry = new BlacklistEntry {
        BlackIp = dto.BlackIp,
        RequesterIp = request.HttpContext.Connection.RemoteIpAddress?.ToString()
    };
    newEntry.AddClient(clientId);
    db.BlacklistEntries.Add(newEntry);
    await db.SaveChangesAsync();

    return Results.Created($"/blacklist/{newEntry.Id}", BlacklistEntryResponse.MapFrom(newEntry));
}).RequireAuthorization("ApiKeyPolicy");

app.MapGet("/blacklist/{id:int}", async (int id, AppDbContext db, ILogger<Program> logger) => {
    logger.LogInformation("Retrieving blacklist entry by ID: {Id}", id);
    var entry = await db.BlacklistEntries.AsNoTracking()
        .FirstOrDefaultAsync(e => e.Id == id);
    return entry is null ? Results.NotFound() : Results.Ok(BlacklistEntryResponse.MapFrom(entry));
}).RequireAuthorization("ApiKeyPolicy");

app.MapGet("/blacklist/{ip}", async (string ip, AppDbContext db, ILogger<Program> logger) => {
    logger.LogInformation("Retrieving blacklist entry by IP: {Ip}", ip);
    var entry = await db.BlacklistEntries.AsNoTracking()
        .FirstOrDefaultAsync(e => e.BlackIp == ip);
    return entry is null ? Results.NotFound() : Results.Ok(BlacklistEntryResponse.MapFrom(entry));
}).RequireAuthorization("ApiKeyPolicy");

app.MapGet("/blacklist", async (AppDbContext db, ILogger<Program> logger) => {
    logger.LogInformation("Retrieving all blacklist entries");
    var entries = await db.BlacklistEntries.AsNoTracking()
        .OrderByDescending(item => item.Frequency)
        .ToListAsync();
    var response = entries.Select(BlacklistEntryResponse.MapFrom);
    return Results.Ok(response);
}).RequireAuthorization("ApiKeyPolicy");

app.Run();