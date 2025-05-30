using JwtAuth.Entities;

namespace JwtAuth.Models
{
    public class AuthInternalResponse
    {
        public required string RefreshToken { get; set; }
        public required string AccessToken { get; set; }
        public User? User { get; set; }
    }
}
