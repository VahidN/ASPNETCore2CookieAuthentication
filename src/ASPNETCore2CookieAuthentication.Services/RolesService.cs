using ASPNETCore2CookieAuthentication.DataLayer.Context;
using ASPNETCore2CookieAuthentication.DomainClasses;
using Microsoft.EntityFrameworkCore;

namespace ASPNETCore2CookieAuthentication.Services;

public class RolesService : IRolesService
{
    private readonly DbSet<Role> _roles;
    private readonly DbSet<User> _users;

    public RolesService(IUnitOfWork uow)
    {
        var unitOfWork = uow ?? throw new ArgumentNullException(nameof(uow));
        _roles = unitOfWork.Set<Role>();
        _users = unitOfWork.Set<User>();
    }

    public Task<List<Role>> FindUserRolesAsync(int userId)
    {
        var userRolesQuery = from role in _roles
            from userRoles in role.UserRoles
            where userRoles.UserId == userId
            select role;

        return userRolesQuery.OrderBy(x => x.Name).ToListAsync();
    }

    public async Task<bool> IsUserInRole(int userId, string roleName)
    {
        var userRolesQuery = from role in _roles
            where role.Name == roleName
            from user in role.UserRoles
            where user.UserId == userId
            select role;
        var userRole = await userRolesQuery.FirstOrDefaultAsync();
        return userRole != null;
    }

    public Task<List<User>> FindUsersInRoleAsync(string roleName)
    {
        var roleUserIdsQuery = from role in _roles
            where role.Name == roleName
            from user in role.UserRoles
            select user.UserId;
        return _users.Where(user => roleUserIdsQuery.Contains(user.Id))
            .ToListAsync();
    }
}