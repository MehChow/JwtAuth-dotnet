namespace JwtAuth.Models
{
    public class VideoListResult
    {
        public string Title { get; set; } = string.Empty;
        public int VideoId { get; set; }
        public string PublicUrl { get; set; } = string.Empty;
        public string Format { get; set; } = string.Empty;
    }
}
