namespace JwtAuth.Constants
{
    public static class AuthMessages
    {
        // Register
        public const string UsernameAlreadyExists = "USERNAME_ALREADY_EXISTS";

        // Login
        public const string InvalidCredentials = "INVALID_CREDENTIALS";

        // Get user
        public const string UserNotFound = "USER_NOT_FOUND";
        public const string UserIdClaimNotFound = "USER_ID_CLAIM_NOT_FOUND";
        public const string InvalidUserIdFormat = "INVALID_USER_ID_FORMAT";

        // Refresh token
        public const string NoRefreshTokenProvided = "NO_REFRESH_TOKEN_PROVIDED";
        public const string InvalidRefreshToken = "INVALID_REFRESH_TOKEN";

        // Logout
        public const string LogoutSuccess = "LOGOUT_SUCCESS";
    }
}
