using System.ComponentModel.DataAnnotations;
using IpBlacklist.Data.BaseModels;

namespace IpBlacklist.Data.Models;

public class BlacklistEntry : BaseEntity {
    [MaxLength(20)] [Required] public string BlackIp { get; set; } = null!;
    [MaxLength(20)] public string? RequesterIp { get; set; }
    [MaxLength(50)] public string? RegisteredByClient { get; set; }
}