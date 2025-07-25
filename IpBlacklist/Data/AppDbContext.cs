using System.Linq.Expressions;
using System.Text.Json;
using IpBlacklist.Data.BaseModels;
using IpBlacklist.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace IpBlacklist.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options) {
    public DbSet<BlacklistEntry> BlacklistEntries => Set<BlacklistEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) {
        // Apply the query filter to all entities that inherit from BaseEntity
        ApplyQueryFilter(modelBuilder);

        modelBuilder.Entity<BlacklistEntry>(entity => {
            entity.ToTable("BlacklistEntry");

            entity.HasIndex(item => item.BlackIp)
                .IsUnique()
                .HasFilter("[Deleted] = 0");

            var converter = new ValueConverter<List<BlacklistEntry.Client>, string>(
                v => JsonSerializer.Serialize(v, (JsonSerializerOptions)null!),
                v => JsonSerializer.Deserialize<List<BlacklistEntry.Client>>(v, (JsonSerializerOptions)null!) ?? new List<BlacklistEntry.Client>());

            entity
                .Property("_registeredByClients")
                .HasColumnName("RegisteredByClients")
                .HasConversion(converter)
                .HasColumnType("nvarchar(max)");
            modelBuilder.Ignore<BlacklistEntry.Client>();

        });
    }

    private static void ApplyQueryFilter(ModelBuilder modelBuilder) {
        foreach (var entityType in modelBuilder.Model.GetEntityTypes()) {
            if (!typeof(BaseEntity).IsAssignableFrom(entityType.ClrType))
                continue;

            var parameter = Expression.Parameter(entityType.ClrType, "e");
            var deletedProp = Expression.Property(parameter, nameof(BaseEntity.Deleted));
            var filter = Expression.Lambda(
                Expression.Equal(deletedProp, Expression.Constant(false)),
                parameter
            );

            modelBuilder.Entity(entityType.ClrType).HasQueryFilter(filter);
        }
    }
}