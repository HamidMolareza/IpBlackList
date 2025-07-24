using System.Linq.Expressions;
using IpBlacklist.Data.BaseModels;
using IpBlacklist.Data.Models;
using Microsoft.EntityFrameworkCore;

namespace IpBlacklist.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options) {
    public DbSet<BlacklistEntry> BlacklistEntries => Set<BlacklistEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) {
        // Apply the query filter to all entities that inherit from BaseEntity
        ApplyQueryFilter(modelBuilder);

        modelBuilder.Entity<BlacklistEntry>(entity => {
            entity.ToTable("BlacklistEntry");

            entity.HasIndex(item => item.RequesterIp)
                .IsUnique()
                .HasFilter("[Deleted] = 0");
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