using System.Security.Claims;
using ASPNETCore2CookieAuthentication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ASPNETCore2CookieAuthentication.WebApp.Controllers;

[Route("api/[controller]"), Authorize(Policy = CustomRoles.Admin)]
public class MyProtectedAdminApiController : Controller
{
    private readonly IUsersService _usersService;

    public MyProtectedAdminApiController(IUsersService usersService)
    {
        _usersService = usersService ?? throw new ArgumentNullException(nameof(usersService));
    }

    public async Task<IActionResult> Get()
    {
        var claimsIdentity = User.Identity as ClaimsIdentity;
        var userDataClaim = claimsIdentity?.FindFirst(ClaimTypes.UserData);
        var userId = userDataClaim?.Value;

        var id = userId is null ? 0 : int.Parse(userId, NumberStyles.Number, CultureInfo.InvariantCulture);
        return Ok(new
        {
            Id = 1,
            Title = "Hello from My Protected Admin Api Controller!",
            Username = User.Identity?.Name,
            UserData = userId,
            TokenSerialNumber = await _usersService.GetSerialNumberAsync(id)
        });
    }
}