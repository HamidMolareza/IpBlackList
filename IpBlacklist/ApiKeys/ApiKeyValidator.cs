using Microsoft.Extensions.Options;

namespace IpBlacklist.ApiKeys;

public class ApiKeyValidator(IOptions<ApiKeyOptions> options) : IApiKeyValidator {
    private readonly List<ApiKeyEntry> _keys = options.Value.Keys;

    public bool IsValid(string clientId, string secretKey) {
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(secretKey))
            return false;
        return _keys.Count != 0
               && _keys.Any(k => k.ClientId == clientId && k.SecretKey == secretKey);
    }

    public bool IsValid(ApiKeyEntry? entry) {
        return entry is not null
               && IsValid(entry.ClientId, entry.SecretKey);
    }

    public bool IsValid(string? apiKey) {
        var entry = TryParse(apiKey);

        return entry is not null
               && IsValid(entry.ClientId, entry.SecretKey);
    }

    public ApiKeyEntry? TryParse(string? apiKey) {
        if (string.IsNullOrWhiteSpace(apiKey))
            return null;

        var parts = apiKey.Split(':');
        if (parts.Length != 2)
            return null;

        return new ApiKeyEntry {
            ClientId = parts[0],
            SecretKey = parts[1]
        };
    }
}