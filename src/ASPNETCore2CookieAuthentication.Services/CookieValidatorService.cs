using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace ASPNETCore2CookieAuthentication.Services;

public class CookieValidatorService(IUsersService usersService, IDeviceDetectionService deviceDetectionService)
    : ICookieValidatorService
{
    private readonly IDeviceDetectionService _deviceDetectionService =
        deviceDetectionService ?? throw new ArgumentNullException(nameof(deviceDetectionService));

    private readonly IUsersService
        _usersService = usersService ?? throw new ArgumentNullException(nameof(usersService));

    public async Task ValidateAsync(CookieValidatePrincipalContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var claimsIdentity = context.Principal?.Identity as ClaimsIdentity;

        if (claimsIdentity?.Claims == null || !claimsIdentity.Claims.Any())
        {
            // this is not our issued cookie
            await HandleUnauthorizedRequest(context);

            return;
        }

        if (!_deviceDetectionService.HasUserTokenValidDeviceDetails(claimsIdentity))
        {
            // Detected usage of an old token from a new device! Please login again!
            await HandleUnauthorizedRequest(context);

            return;
        }

        var serialNumberClaim = claimsIdentity.FindFirst(ClaimTypes.SerialNumber);

        if (serialNumberClaim == null)
        {
            // this is not our issued cookie
            await HandleUnauthorizedRequest(context);

            return;
        }

        var userIdString = claimsIdentity.FindFirst(ClaimTypes.UserData)?.Value;

        if (!int.TryParse(userIdString, NumberStyles.Number, CultureInfo.InvariantCulture, out var userId))
        {
            // this is not our issued cookie
            await HandleUnauthorizedRequest(context);

            return;
        }

        var user = await _usersService.FindUserAsync(userId);

        if (user == null || !string.Equals(user.SerialNumber, serialNumberClaim.Value, StringComparison.Ordinal) ||
            !user.IsActive)
        {
            // user has changed his/her password/roles/stat/IsActive
            await HandleUnauthorizedRequest(context);
        }

        await _usersService.UpdateUserLastActivityDateAsync(userId);
    }

    private static Task HandleUnauthorizedRequest(CookieValidatePrincipalContext context)
    {
        context.RejectPrincipal();

        return context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }
}