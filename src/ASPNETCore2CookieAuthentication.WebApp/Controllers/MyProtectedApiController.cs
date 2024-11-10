using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ASPNETCore2CookieAuthentication.WebApp.Controllers;

[ApiController]
[Route(template: "api/[controller]")]
[Authorize]
public class MyProtectedApiController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
        => Ok(new
        {
            Id = 1,
            Title = "Hello from My Protected Controller!",
            Username = User.Identity?.Name
        });
}