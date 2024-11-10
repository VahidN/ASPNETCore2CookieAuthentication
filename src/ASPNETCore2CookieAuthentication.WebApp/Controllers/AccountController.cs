using System.Security.Claims;
using ASPNETCore2CookieAuthentication.DomainClasses;
using ASPNETCore2CookieAuthentication.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;

namespace ASPNETCore2CookieAuthentication.WebApp.Controllers;

[ApiController]
[Route(template: "api/[controller]")]
[EnableCors(policyName: "CorsPolicy")]
public class AccountController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly IDeviceDetectionService _deviceDetectionService;
    private readonly IRolesService _rolesService;
    private readonly IUsersService _usersService;

    public AccountController(IUsersService usersService,
        IRolesService rolesService,
        IConfiguration configuration,
        IDeviceDetectionService deviceDetectionService)
    {
        _usersService = usersService ?? throw new ArgumentNullException(nameof(usersService));
        _rolesService = rolesService ?? throw new ArgumentNullException(nameof(rolesService));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));

        _deviceDetectionService =
            deviceDetectionService ?? throw new ArgumentNullException(nameof(deviceDetectionService));
    }

    [AllowAnonymous]
    [HttpPost(template: "[action]")]
    public async Task<IActionResult> Login([FromBody] User loginUser)
    {
        if (loginUser == null)
        {
            return BadRequest(error: "user is not set.");
        }

        var user = await _usersService.FindUserAsync(loginUser.Username, loginUser.Password);

        if (user?.IsActive != true)
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return Unauthorized();
        }

        var loginCookieExpirationDays = _configuration.GetValue(key: "LoginCookieExpirationDays", defaultValue: 30);
        var cookieClaims = await createCookieClaimsAsync(user);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, cookieClaims,
            new AuthenticationProperties
            {
                IsPersistent = true, // "Remember Me"
                IssuedUtc = DateTimeOffset.UtcNow,
                ExpiresUtc = DateTimeOffset.UtcNow.AddDays(loginCookieExpirationDays)
            });

        await _usersService.UpdateUserLastActivityDateAsync(user.Id);

        return Ok();
    }

    private async Task<ClaimsPrincipal> createCookieClaimsAsync(User user)
    {
        var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString(CultureInfo.InvariantCulture)));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.Username));
        identity.AddClaim(new Claim(type: "DisplayName", user.DisplayName ?? ""));

        // to invalidate the cookie
        identity.AddClaim(new Claim(ClaimTypes.SerialNumber, user.SerialNumber ?? ""));

        identity.AddClaim(new Claim(ClaimTypes.System, _deviceDetectionService.GetCurrentRequestDeviceDetailsHash(),
            ClaimValueTypes.String));

        // custom data
        identity.AddClaim(new Claim(ClaimTypes.UserData, user.Id.ToString(CultureInfo.InvariantCulture)));

        // add roles
        var roles = await _rolesService.FindUserRolesAsync(user.Id);

        foreach (var role in roles)
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, role.Name));
        }

        return new ClaimsPrincipal(identity);
    }

    [AllowAnonymous]
    [HttpGet(template: "[action]")]
    [HttpPost(template: "[action]")]
    public async Task<bool> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return true;
    }

    [HttpGet(template: "[action]")]
    [HttpPost(template: "[action]")]
    public bool IsAuthenticated() => User.Identity?.IsAuthenticated ?? false;

    [HttpGet(template: "[action]")]
    [HttpPost(template: "[action]")]
    public IActionResult GetUserInfo()
    {
        var claimsIdentity = User.Identity as ClaimsIdentity;

        return Ok(new
        {
            Username = claimsIdentity?.Name
        });
    }
}