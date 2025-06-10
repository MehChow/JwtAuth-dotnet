using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace JwtAuth.Entities
{
    public class Video
    {
        [Key]
        public int Id { get; set; }
        public required string Title { get; set; }
        public string? Description { get; set; }
        public required string PublicUrl { get; set; }
        public required VideoFormat Format { get; set; }
        public Guid UserId { get; set; } // Changed to Guid
        [ForeignKey("UserId")]
        public required User User { get; set; } // Navigation property
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
