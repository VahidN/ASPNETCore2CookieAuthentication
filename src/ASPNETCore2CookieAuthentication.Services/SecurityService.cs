using System.Text;

namespace ASPNETCore2CookieAuthentication.Services;

public class SecurityService : ISecurityService
{
    public string GetSha256Hash(string input)
    {
        var byteValue = Encoding.UTF8.GetBytes(input);
        var byteHash = SHA256.HashData(byteValue);

        return Convert.ToBase64String(byteHash);
    }
}