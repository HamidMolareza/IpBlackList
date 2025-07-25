using System.ComponentModel.DataAnnotations;
using IpBlacklist.Data.BaseModels;

namespace IpBlacklist.Data.Models;

public class BlacklistEntry : BaseEntity {
    [MaxLength(20)] [Required] public string BlackIp { get; set; } = null!;

    [MaxLength(20)] public string? RequesterIp { get; set; }

    // Private backing field
    private readonly List<Client> _registeredByClients = [];

    // Public read-only access
    public IReadOnlyList<Client> RegisteredByClients => _registeredByClients;

    public int Frequency {
        get => _registeredByClients.Count;
        private set { } // For EF
    }

    // Method to add client
    public void AddClient(string clientId) {
        clientId = clientId.ToLower();
        if (!ClientExist(clientId)) {
            _registeredByClients.Add(new Client(clientId));
        }
    }

    public bool ClientExist(string clientId) {
        clientId = clientId.ToLower();
        return _registeredByClients.Exists(c => c.Name == clientId);
    }

    public class Client(string name) {
        private string _name = name;
        private DateTime _dateTimeUtc;

        public string Name {
            get => _name;
            set {
                if (string.IsNullOrWhiteSpace(value))
                    throw new ArgumentNullException(value);
                _name = value.ToLower();
            }
        }

        public DateTime DateTimeUtc {
            get => _dateTimeUtc == default ? DateTime.UtcNow : _dateTimeUtc;
            set => _dateTimeUtc = value;
        }
    }
}