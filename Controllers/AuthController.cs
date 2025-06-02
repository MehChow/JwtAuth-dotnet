using Microsoft.AspNetCore.Mvc;
using JwtAuth.Models;
using JwtAuth.Services;
using JwtAuth.Constants;
using Microsoft.AspNetCore.Authorization;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(
        IAuthService authService,
        IOAuthService oAuthService,
        ICookieService cookieService,
        IConfiguration configuration,
        ILogger<AuthController> logger) : ControllerBase
    {
        private readonly bool _isProduction = configuration.GetValue<bool>("AppSettings:IsProduction");

        [HttpPost("register")]
        public async Task<ActionResult<UserResponseDto>> Register(RegisterDto request)
        {
            var result = await authService.RegisterAsync(request);
            if (!result.IsSuccess)
            {
                if (result.Message == AuthMessages.USERNAME_ALREADY_EXISTS)
                {
                    return Conflict(result.Message);
                }
                return StatusCode(500, result.Message);
            }

            var requestResponse = result.Data;
            cookieService.SetAuthCookies(Response, requestResponse.AccessToken, requestResponse.RefreshToken, _isProduction);

            var userResponse = new UserResponseDto
            {
                Id = requestResponse.User.Id,
                Username = requestResponse.User.Username,
                Role = requestResponse.User.Role
            };

            return Ok(userResponse);
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserResponseDto>> Login(LoginDto request)
        {
            var result = await authService.LoginAsync(request);
            if (!result.IsSuccess)
            {
                if (result.Message == AuthMessages.INVALID_CREDENTIALS)
                {
                    return Unauthorized(result.Message);
                }
                return StatusCode(500, result.Message);
            }

            var loginResponse = result.Data!;
            cookieService.SetAuthCookies(Response, loginResponse.AccessToken, loginResponse.RefreshToken, _isProduction);

            var userResponse = new UserResponseDto
            {
                Id = loginResponse.User.Id,
                Username = loginResponse.User.Username,
                Role = loginResponse.User.Role
            };

            return Ok(userResponse);
        }

        [Authorize]
        [HttpGet("get-userinfo")]
        public async Task<ActionResult<UserResponseDto>> GetUserInfo()
        {
            var result = await authService.GetUserInfoAsync();
            if (!result.IsSuccess)
            {
                if (result.Message == AuthMessages.INVALID_USER_ID_FORMAT)
                {
                    return Unauthorized(result.Message);
                }
                if (result.Message == AuthMessages.USER_NOT_FOUND)
                {
                    return NotFound(result.Message);
                }
                return StatusCode(500, result.Message);
            }

            var user = result.Data!;
            var userResponse = new UserResponseDto
            {
                Id = user.Id,
                Username = user.Username,
                Role = user.Role
            };

            return Ok(userResponse);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
            {
                return BadRequest(AuthMessages.NO_REFRESH_TOKEN_PROVIDED);
            }

            var result = await authService.RefreshTokenAsync(refreshToken);
            if (!result.IsSuccess)
            {
                if (result.Message == AuthMessages.INVALID_REFRESH_TOKEN)
                {
                    cookieService.ClearAuthCookies(Response, _isProduction);
                    return Unauthorized(result.Message);
                }
                return StatusCode(500, result.Message);
            }

            var response = result.Data!;
            cookieService.SetAuthCookies(Response, response.AccessToken, response.RefreshToken, _isProduction);

            logger.LogInformation("Set-Cookie headers: {Headers}", string.Join(", ", Response.Headers["Set-Cookie"].ToArray()));
            return Ok();
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var accessToken = Request.Cookies["accessToken"];

            var result = await authService.LogoutAsync(refreshToken, accessToken);
            cookieService.ClearAuthCookies(Response, _isProduction);

            return Ok(result.Message);
        }

        [HttpPost("google")]
        public async Task<ActionResult<UserResponseDto>> GoogleLogin([FromBody] GoogleAuthRequest request)
        {
            // 1. Exchange code for tokens using OAuthService
            var tokenResponse = await oAuthService.ExchangeCodeForTokensAsync(request.Code);

            // 2. Authenticate with ID token using AuthService
            var authResult = await authService.GoogleLoginAsync(tokenResponse.Id_token);

            if (!authResult.IsSuccess)
            {
                return Unauthorized(authResult.Message);
            }

            // 3. Set cookies and return user info
            var authData = authResult.Data!;
            cookieService.SetAuthCookies(Response, authData.AccessToken, authData.RefreshToken, _isProduction);

            return Ok(new UserResponseDto
            {
                Id = authData.User!.Id,
                Username = authData.User.Username,
                Role = authData.User.Role
            });
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
