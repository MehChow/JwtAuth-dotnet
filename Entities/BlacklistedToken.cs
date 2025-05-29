namespace JwtAuth.Entities
{
    public class BlacklistedToken
    {
        public string Jti { get; set; } = null!;
        public DateTime ExpiryDate { get; set; }
    }
}
