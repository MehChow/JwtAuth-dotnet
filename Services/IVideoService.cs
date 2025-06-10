using JwtAuth.Models;

namespace JwtAuth.Services
{
    public interface IVideoService
    {
        Task<VideoListResult[]> GetAllVideosAsync();
    }
}
