namespace IpBlacklist.Data.BaseModels;

public abstract class AuditableEntity {
    public DateTime CreatedUtc { get; set; }
    public DateTime? DeleteUtc { get; set; }
}