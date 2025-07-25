namespace IpBlacklist.ApiKeys;

public class ApiKeyEntry {
    private string _clientId = string.Empty;

    public string ClientId {
        get => _clientId;
        set => _clientId = value.ToLower();
    }

    public string SecretKey { get; set; } = string.Empty;
}