namespace JwtAuth.Exceptions
{
    public class AuthException(string message, Exception? innerException = null)
    : Exception(message, innerException);
}
