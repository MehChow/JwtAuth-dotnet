using JwtAuth.Data;
using JwtAuth.Models;
using Microsoft.EntityFrameworkCore;

namespace JwtAuth.Services
{
    public class VideoService(UserDbContext context, ILogger<AuthService> logger) : IVideoService
    {
        public async Task<VideoListResult[]> GetAllVideosAsync()
        {
            var videos = await context.Videos.Select(v => new VideoListResult
            {
                Title = v.Title,
                VideoId = v.Id,
                PublicUrl = v.PublicUrl,
                Format = v.Format.ToString()
            }).ToListAsync();

            return [.. videos];
        }
    }
}
