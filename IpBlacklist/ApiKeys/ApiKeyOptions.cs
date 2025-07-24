namespace IpBlacklist.ApiKeys;

public class ApiKeyOptions {
    public const string OptionName = "ApiKeys";
    public List<ApiKeyEntry> Keys { get; set; } = [];
}