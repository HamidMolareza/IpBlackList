using IpBlacklist.Data.BaseModels;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace IpBlacklist.Data.Interceptors;

public class CreatedInterceptor : SaveChangesInterceptor {
    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result) {
        SetCreated(eventData.Context);
        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default) {
        SetCreated(eventData.Context);
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    private void SetCreated(DbContext? context) {
        if (context == null) return;

        var entries = context.ChangeTracker.Entries<AuditableEntity>()
            .Where(e => e.State == EntityState.Added);

        foreach (var entry in entries) {
            entry.Entity.CreatedUtc = DateTime.UtcNow;
        }
    }
}