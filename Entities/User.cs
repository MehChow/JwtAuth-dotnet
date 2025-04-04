﻿namespace JwtAuth.Entities
{
    public class User
    {
        public Guid Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string? PasswordHash { get; set; } = string.Empty;
        public string Role { get; set; } = "User";
        public string? Provider { get; set; } // "Local", "Google", "GitHub"
        public string? ProviderId { get; set; } // Unique ID from OAuth provider
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
    }
}
