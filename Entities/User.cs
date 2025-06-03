namespace JwtAuth.Entities
{
    public class User
    {
        public Guid Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? PasswordHash { get; set; } = string.Empty;
        public string Role { get; set; } = "User";
        public string? Provider { get; set; } // "Local", "Google", "GitHub"
        public string? ProviderId { get; set; } // Unique ID from OAuth provider
        public List<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>(); // Navigation property
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
