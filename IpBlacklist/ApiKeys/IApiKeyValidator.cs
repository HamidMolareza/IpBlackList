namespace IpBlacklist.ApiKeys;

public interface IApiKeyValidator {
    bool IsValid(string clientId, string secretKey);
    bool IsValid(ApiKeyEntry? entry);
    bool IsValid(string? apiKey);
    ApiKeyEntry? TryParse(string? apiKey);
}