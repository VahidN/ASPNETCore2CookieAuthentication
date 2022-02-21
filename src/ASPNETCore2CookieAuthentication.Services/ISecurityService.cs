namespace ASPNETCore2CookieAuthentication.Services;

public interface ISecurityService
{
    string GetSha256Hash(string input);
}