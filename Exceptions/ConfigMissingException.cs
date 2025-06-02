namespace JwtAuth.Exceptions
{
    public class ConfigMissingException(string configKey)
        : Exception($"Missing required configuration: {configKey}");
}
