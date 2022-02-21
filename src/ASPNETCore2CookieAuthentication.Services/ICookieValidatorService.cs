using Microsoft.AspNetCore.Authentication.Cookies;

namespace ASPNETCore2CookieAuthentication.Services;

public interface ICookieValidatorService
{
    Task ValidateAsync(CookieValidatePrincipalContext context);
}