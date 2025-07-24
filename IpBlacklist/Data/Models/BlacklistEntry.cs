using System.ComponentModel.DataAnnotations;
using IpBlacklist.Data.BaseModels;

namespace IpBlacklist.Data.Models;

public class BlacklistEntry : BaseEntity {
    [MaxLength(20)] [Required] public string BlackIp { get; set; } = null!;

    [MaxLength(20)] public string? RequesterIp { get; set; }

    // Private backing field
    private readonly List<string> _registeredByClients = [];

    // Public read-only access
    public IReadOnlyList<string> RegisteredByClients => _registeredByClients;

    public int Frequency {
        get => _registeredByClients.Count;
        private set { } // For EF
    }

    // Method to add client
    public void AddClient(string clientId) {
        clientId = clientId.ToLower();
        if (!_registeredByClients.Contains(clientId)) {
            _registeredByClients.Add(clientId);
        }
    }

    // Optional: method to remove client
    public void RemoveClient(string clientId) {
        clientId = clientId.ToLower();
        _registeredByClients.Remove(clientId);
    }
}