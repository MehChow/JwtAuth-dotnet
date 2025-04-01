using Microsoft.AspNetCore.Mvc;
using JwtAuth.Entities;
using JwtAuth.Models;
using JwtAuth.Services;
using JwtAuth.Constants;
using Microsoft.AspNetCore.Authorization;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService, IConfiguration configuration, ILogger<AuthController> _logger) : ControllerBase
    {
        private readonly bool isProduction = configuration.GetValue<bool>("AppSettings:IsProduction");

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(RegisterDto request)
        {
            var result = await authService.RegisterAsync(request);
            if (!result.IsSuccess)
            {
                // Username already exists
                if (result.Message == AuthMessages.UsernameAlreadyExists)
                {
                    return Conflict(result.Message);
                }

                // Db or server error
                return StatusCode(500, result.Message);
            }

            // Set the accessToken and refreshToken as HTTP-only cookies
            var (tokenResponse, refreshToken, user) = result.Data;
            Response.Cookies.Append("accessToken", tokenResponse.AccessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(15)
            });
            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7)
            });

            // Only return the neccessary info
            var userResponse = new UserResponseDto
            {
                Id = user.Id,
                Username = user.Username,
                Role = user.Role
            };

            // Return the access token and the user
            return CreatedAtAction("GetUser", new { id = user.Id }, new
            {
                tokenResponse,
                userResponse
            });
        }

        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(LoginDto request)
        {
            var result = await authService.LoginAsync(request);
            if (!result.IsSuccess)
            {
                // Invalid credentials
                if (result.Message == AuthMessages.InvalidCredentials)
                {
                    return Unauthorized(result.Message);
                }

                // Server error
                return StatusCode(500, result.Message);
            }

            // Set the accessToken and refreshToken as HTTP-only cookies
            var (tokenResponse, refreshToken, user) = result.Data;
            Response.Cookies.Append("accessToken", tokenResponse.AccessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(15)
            });
            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7)
            });

            // Only return the neccessary info
            var userResponse = new UserResponseDto
            {
                Id = user.Id,
                Username = user.Username,
                Role = user.Role
            };

            // Return the access token and the user
            return Ok(new
            {
                tokenResponse,
                userResponse
            });
        }

        [Authorize]
        [HttpGet("get-userinfo")]
        public async Task<ActionResult<UserResponseDto>> GetUserInfo()
        {
            var result = await authService.GetUserInfoAsync();
            if (!result.IsSuccess)
            {
                if (result.Message == AuthMessages.UserIdClaimNotFound || result.Message == AuthMessages.InvalidUserIdFormat)
                {
                    return Unauthorized(result.Message);
                }

                if (result.Message == AuthMessages.UserNotFound)
                {
                    return NotFound(result.Message);
                }

                // Server error
                return StatusCode(500, result.Message);
            }

            var user = result.Data;

            // Only return necessary info
            var userResponse = new UserResponseDto
            {
                Id = user.Id,
                Username = user.Username,
                Role = user.Role
            };

            return Ok(userResponse);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<RefreshTokenResponseDto>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
            {
                // No refresh token provided
                return BadRequest(AuthMessages.NoRefreshTokenProvided);
            }

            var result = await authService.RefreshTokenAsync(refreshToken);
            if (!result.IsSuccess)
            {
                // Invalid refresh token
                if (result.Message == AuthMessages.InvalidRefreshToken)
                {
                    return Unauthorized(result.Message);
                }

                // Server error
                return StatusCode(500, result.Message);
            }

            var user = await authService.GetUserByRefreshTokenAsync(refreshToken);
            var newRefreshToken = await authService.GenerateAndSaveRefreshTokenAsync(user!);

            // Set the accessToken and refreshToken as HTTP-only cookies
            Response.Cookies.Append("accessToken", result.Data.AccessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(15)
            });

            Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7)
            });

            // Return the new access token
            _logger.LogInformation("Set-Cookie headers: {Headers}", string.Join(", ", Response.Headers["Set-Cookie"].ToArray())); 
            return Ok(new
            {
                accessToken = result.Data.AccessToken,
                refreshToken = newRefreshToken
            });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            // Call the service even if refreshToken is null/empty, as it will handle it gracefully
            var result = await authService.LogoutAsync(refreshToken);

            // Clear cookies regardless of token state
            Response.Cookies.Delete("accessToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict
            });
            Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict
            });

            return Ok(result.Message);
        }

        [Authorize]
        [HttpGet]
        public IActionResult AuthenticationOnlyEndpoint()
        {
            return Ok("You are authenticated!!");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnlyEndpoint()
        {
            return Ok("You are an admin!!");
        }
    }   
}
