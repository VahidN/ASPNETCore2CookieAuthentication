using ASPNETCore2CookieAuthentication.DataLayer.Context;
using ASPNETCore2CookieAuthentication.DomainClasses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ASPNETCore2CookieAuthentication.Services;

public class DbInitializerService(IServiceScopeFactory scopeFactory, ISecurityService securityService)
    : IDbInitializerService
{
    private readonly IServiceScopeFactory _scopeFactory =
        scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));

    private readonly ISecurityService _securityService =
        securityService ?? throw new ArgumentNullException(nameof(securityService));

    public void Initialize()
    {
        using var serviceScope = _scopeFactory.CreateScope();

        using var context = serviceScope.ServiceProvider.GetService<ApplicationDbContext>() ??
                            throw new InvalidOperationException(message: "context is null");

        context.Database.Migrate();
    }

    public void SeedData()
    {
        using var serviceScope = _scopeFactory.CreateScope();

        using var context = serviceScope.ServiceProvider.GetService<ApplicationDbContext>() ??
                            throw new InvalidOperationException(message: "context is null");

        // Add default roles
        var adminRole = new Role
        {
            Name = CustomRoles.Admin
        };

        var userRole = new Role
        {
            Name = CustomRoles.User
        };

        if (!context.Roles.Any())
        {
            context.Add(adminRole);
            context.Add(userRole);
            context.SaveChanges();
        }

        // Add Admin user
        if (!context.Users.Any())
        {
            var adminUser = new User
            {
                Username = "Vahid",
                DisplayName = "وحيد",
                IsActive = true,
                LastLoggedIn = null,
                Password = _securityService.GetSha256Hash(input: "1234"),
                SerialNumber = Guid.NewGuid().ToString(format: "N")
            };

            context.Add(adminUser);
            context.SaveChanges();

            context.Add(new UserRole
            {
                Role = adminRole,
                User = adminUser
            });

            context.Add(new UserRole
            {
                Role = userRole,
                User = adminUser
            });

            context.SaveChanges();
        }
    }
}