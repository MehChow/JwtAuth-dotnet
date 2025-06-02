using System.Net.Http.Headers;
using JwtAuth.Models;
using JwtAuth.Exceptions;

namespace JwtAuth.Services
{
    public class OAuthService(IHttpClientFactory httpClientFactory, IConfiguration config) : IOAuthService
    {
        public async Task<GoogleTokenResponse> ExchangeCodeForTokensAsync(string authorizationCode)
        {
            using var client = httpClientFactory.CreateClient();
            client.BaseAddress = new Uri("https://oauth2.googleapis.com");
            client.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));

            var requestData = new Dictionary<string, string>
            {
                ["code"] = authorizationCode,
                ["client_id"] = config["Authentication:Google:ClientId"]
                    ?? throw new ConfigMissingException("Google:ClientId"),
                ["client_secret"] = config["Authentication:Google:ClientSecret"]
                    ?? throw new ConfigMissingException("Google:ClientSecret"),
                ["redirect_uri"] = config["Authentication:Google:RedirectUri"]
                    ?? throw new ConfigMissingException("Google:RedirectUri"),
                ["grant_type"] = "authorization_code"
            };

            using var response = await client.PostAsync(
                "/token",
                new FormUrlEncodedContent(requestData));

            response.EnsureSuccessStatusCode();

            return await response.Content.ReadFromJsonAsync<GoogleTokenResponse>()
                ?? throw new InvalidOperationException("Failed to deserialize token response");
        }
    }
}
