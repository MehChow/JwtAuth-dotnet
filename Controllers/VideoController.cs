using JwtAuth.Models;
using JwtAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class VideoController(IVideoService videoService,
ILogger<AuthController> logger) : ControllerBase
    {
        [HttpGet]
        public async Task<ActionResult<VideoListResult>> GetAllVideos()
        {
            var result = await videoService.GetAllVideosAsync();
            return Ok(result);
        }
    }
}
