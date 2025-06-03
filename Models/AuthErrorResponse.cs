namespace JwtAuth.Models
{
    public class AuthErrorResponse
    {
        public required string Message { get; set; }
        public required string Code { get; set; }
    }
}
