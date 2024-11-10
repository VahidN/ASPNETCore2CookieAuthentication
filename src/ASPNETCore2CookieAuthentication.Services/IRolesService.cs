using ASPNETCore2CookieAuthentication.DomainClasses;

namespace ASPNETCore2CookieAuthentication.Services;

public interface IRolesService
{
    Task<List<Role>> FindUserRolesAsync(int userId);

    Task<bool> IsUserInRole(int userId, string roleName);

    Task<List<User>> FindUsersInRoleAsync(string roleName);
}