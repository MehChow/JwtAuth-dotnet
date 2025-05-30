namespace JwtAuth.Constants
{
    public static class AuthMessages
    {
        // Register
        public const string USERNAME_ALREADY_EXISTS = "USERNAME_ALREADY_EXISTS";

        // Login
        public const string INVALID_CREDENTIALS = "INVALID_CREDENTIALS";

        // Get user
        public const string USER_NOT_FOUND = "USER_NOT_FOUND";
        public const string USER_ID_CLAIM_NOT_FOUND = "USER_ID_CLAIM_NOT_FOUND";
        public const string INVALID_USER_ID_FORMAT = "INVALID_USER_ID_FORMAT";

        // Refresh token
        public const string NO_REFRESH_TOKEN_PROVIDED = "NO_REFRESH_TOKEN_PROVIDED";
        public const string INVALID_REFRESH_TOKEN = "INVALID_REFRESH_TOKEN";

        // Logout
        public const string LOGOUT_SUCCESS = "LOGOUT_SUCCESS";
    }
}
