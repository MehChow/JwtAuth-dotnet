using System.ComponentModel.DataAnnotations;

namespace JwtAuth.Models
{
    public class RegisterDto
    {
        [Required]
        public string Email { get; set; } = string.Empty;

        [Required]
        [MinLength(6)]
        public string Password { get; set; } = string.Empty;
    }
}
