using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ASPNETCore2CookieAuthentication.WebApp.Controllers;

[Route("api/[controller]"), Authorize]
public class MyProtectedApiController : Controller
{
    public IActionResult Get()
    {
        return Ok(new
        {
            Id = 1,
            Title = "Hello from My Protected Controller!",
            Username = User.Identity?.Name
        });
    }
}