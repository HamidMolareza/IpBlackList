using System.Globalization;
using System.Text;

namespace IpBlacklist.Helpers;

public static class SyncTokenHelper {
    public static string EncodeToken(DateTime timestamp) {
        var utc = timestamp.Kind switch {
            DateTimeKind.Utc => timestamp,
            DateTimeKind.Local => timestamp.ToUniversalTime(),
            DateTimeKind.Unspecified => DateTime.SpecifyKind(timestamp, DateTimeKind.Utc), // assume UTC if unknown
            _ => timestamp
        };

        var iso = utc.ToString("O");
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(iso));
    }

    public static DateTime? DecodeToken(string? token) {
        if (string.IsNullOrWhiteSpace(token))
            return null;

        try {
            var iso = Encoding.UTF8.GetString(Convert.FromBase64String(token));
            return DateTime.Parse(iso, null, DateTimeStyles.RoundtripKind);
        }
        catch {
            return null;
        }
    }
}