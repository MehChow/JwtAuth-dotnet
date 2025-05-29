namespace JwtAuth.Entities
{
    public class RefreshToken
    {
        public int Id { get; set; } // Maps to Id (INT, PRIMARY KEY)
        public Guid UserId { get; set; } // Maps to UserId (UNIQUEIDENTIFIER)
        public string TokenHash { get; set; } = null!; // Maps to TokenHash (NVARCHAR(256))
        public DateTime IssuedAt { get; set; } // Maps to IssuedAt (DATETIME)
        public DateTime ExpiresAt { get; set; } // Maps to ExpiresAt (DATETIME)
        public bool IsRevoked { get; set; } // Maps to IsRevoked (BIT)
        public User User { get; set; } = null!; // Navigation property to User
    }
}
