using IpBlacklist.Data.Models;

namespace IpBlacklist.Models;

public class BlacklistEntryResponse {
    public int Id { get; set; }
    public string BlackIp { get; set; } = string.Empty;
    public DateTime CreatedUtc { get; set; }

    public static BlacklistEntryResponse MapFrom(BlacklistEntry entry) =>
        new() {
            Id = entry.Id,
            BlackIp = entry.BlackIp,
            CreatedUtc = entry.CreatedUtc
        };
}