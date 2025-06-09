using Microsoft.AspNetCore.Mvc;
using JwtAuth.Models;
using JwtAuth.Services;
using JwtAuth.Constants;
using Microsoft.AspNetCore.Authorization;
using JwtAuth.Entities;

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
                logger.LogWarning("Registration failed: {Message}", result.Message);

                // Email already in use
                if (result.Message == AuthMessages.EMAIL_ALREADY_INUSED)
                {
                    return Conflict(new AuthErrorResponse
                    {
                        Message = "This email is already registered",
                        Code = "EMAIL_IN_USE"
                    });
                }

                return StatusCode(500, new AuthErrorResponse
                {
                    Message = "Registration failed. Please try again later.",
                    Code = "REGISTRATION_ERROR"
                });
            }

            var requestResponse = result.Data!;
            cookieService.SetAuthCookies(Response, requestResponse.AccessToken, requestResponse.RefreshToken, _isProduction);

            return Ok(MapToUserResponse(requestResponse.User!));
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserResponseDto>> Login(LoginDto request)
        {
            var result = await authService.LoginAsync(request);
            if (!result.IsSuccess)
            {
                logger.LogWarning("Login failed: {Message}", result.Message);

                // Invalid credentials
                if (result.Message == AuthMessages.INVALID_CREDENTIALS)
                {
                    return Unauthorized(new AuthErrorResponse
                    {
                        Message = "Invalid email or password",
                        Code = "INVALID_CREDENTIALS"
                    });
                }

                return StatusCode(500, new AuthErrorResponse
                {
                    Message = "Login failed. Please try again later.",
                    Code = "LOGIN_ERROR"
                });
            }

            var loginResponse = result.Data!;
            cookieService.SetAuthCookies(Response, loginResponse.AccessToken, loginResponse.RefreshToken, _isProduction);

            return Ok(MapToUserResponse(loginResponse.User!));
        }

        [Authorize]
        [HttpGet("get-userinfo")]
        public async Task<ActionResult<UserResponseDto>> GetUserInfo()
        {
            var result = await authService.GetUserInfoAsync();
            if (!result.IsSuccess)
            {
                logger.LogWarning("Failed to get user info: {Message}", result.Message);

                // Return generic error for users
                return StatusCode(500, new AuthErrorResponse
                {
                    Message = "Unable to retrieve user information. Please try logging in again.",
                    Code = "AUTH_ERROR"
                });
            }

            var user = result.Data!;
            var userResponse = new UserResponseDto
            {
                Id = user.Id,
                Email = user.Email,
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
                // No refresh token provided
                return BadRequest(new AuthErrorResponse
                {
                    Message = "No refresh token provided",
                    Code = "NO_REFRESH_TOKEN"
                });
            }

            var result = await authService.RefreshTokenAsync(refreshToken);
            if (!result.IsSuccess)
            {
                logger.LogWarning("Token refresh failed: {Message}", result.Message);

                // Invalid refresh token
                if (result.Message == AuthMessages.INVALID_REFRESH_TOKEN)
                {
                    cookieService.ClearAuthCookies(Response, _isProduction);
                    return Unauthorized(new AuthErrorResponse
                    {
                        Message = "Session expired. Please log in again.",
                        Code = "INVALID_REFRESH_TOKEN"
                    });
                }

                return StatusCode(500, new AuthErrorResponse
                {
                    Message = "Failed to refresh session. Please log in again.",
                    Code = "REFRESH_ERROR"
                });
            }

            var response = result.Data!;
            cookieService.SetAuthCookies(Response, response.AccessToken, response.RefreshToken, _isProduction);

            return Ok();
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var accessToken = Request.Cookies["accessToken"];

            // Nothing needs to be return from service, just clear cookies
            await authService.LogoutAsync(refreshToken, accessToken);
            cookieService.ClearAuthCookies(Response, _isProduction);

            return Ok(new AuthErrorResponse
            {
                Message = "Successfully logged out",
                Code = "LOGOUT_SUCCESS"
            });
        }

        [HttpPost("google")]
        public async Task<ActionResult<UserResponseDto>> GoogleLogin([FromBody] GoogleAuthRequest request)
        {
            // need a trycatch block because it's making a HTTP requests to Google's servers
            // If fails, error will be caught and logged
            try
            {
                // 1. Exchange code for tokens using OAuthService
                var tokenResponse = await oAuthService.ExchangeCodeForTokensAsync(request.Code);

                // 2. Authenticate with ID token using AuthService
                var authResult = await authService.GoogleLoginAsync(tokenResponse.Id_token);

                if (!authResult.IsSuccess)
                {
                    logger.LogWarning("Google login failed: {Message}", authResult.Message);
                    return Unauthorized(new AuthErrorResponse
                    {
                        Message = "Google authentication failed. Please try again.",
                        Code = "GOOGLE_AUTH_ERROR"
                    });
                }

                // 3. Set cookies and return user info
                var authData = authResult.Data!;
                cookieService.SetAuthCookies(Response, authData.AccessToken, authData.RefreshToken, _isProduction);

                return Ok(MapToUserResponse(authData.User!));
            }
            catch (Exception ex) {
                logger.LogError(ex, "Unexpected error during Google login");

                return StatusCode(500, new AuthErrorResponse
                {
                    Message = "Google authentication failed. Please try again later.",
                    Code = "GOOGLE_AUTH_ERROR"
                });
            }
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

        [HttpGet("health")]
        public IActionResult HealthCheck()
        {
            return Ok("API is operational!!!");
        }

        // Helper method to map User to UserResponseDto
        private static UserResponseDto MapToUserResponse(User user)
        {
            return new UserResponseDto
            {
                Id = user.Id,
                Email = user.Email,
                Username = user.Username,
                Role = user.Role
            };
        }
    }   
}
