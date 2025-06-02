namespace JwtAuth.Models
{
    public class GoogleTokenResponse
    {
        public required string Access_token { get; set; }
        public required string Id_token { get; set; }
        public required int Expires_in { get; set; }
        public required string Token_type { get; set; }
        public string? Refresh_token { get; set; }
    }
}
