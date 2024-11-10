using ASPNETCore2CookieAuthentication.DataLayer.Context;
using ASPNETCore2CookieAuthentication.DomainClasses;
using Microsoft.EntityFrameworkCore;

namespace ASPNETCore2CookieAuthentication.Services;

public class UsersService : IUsersService
{
    private readonly ISecurityService _securityService;
    private readonly IUnitOfWork _uow;
    private readonly DbSet<User> _users;

    public UsersService(IUnitOfWork uow, ISecurityService securityService)
    {
        _uow = uow ?? throw new ArgumentNullException(nameof(uow));
        _users = _uow.Set<User>();
        _securityService = securityService ?? throw new ArgumentNullException(nameof(securityService));
    }

    public ValueTask<User?> FindUserAsync(int userId) => _users.FindAsync(userId);

    public Task<User?> FindUserAsync(string username, string password)
    {
        var passwordHash = _securityService.GetSha256Hash(password);

        return _users.FirstOrDefaultAsync(x => x.Username == username && x.Password == passwordHash);
    }

    public async Task<string?> GetSerialNumberAsync(int userId)
    {
        var user = await FindUserAsync(userId);

        return user?.SerialNumber;
    }

    public async Task UpdateUserLastActivityDateAsync(int userId)
    {
        var user = await FindUserAsync(userId);

        if (user is null)
        {
            return;
        }

        if (user.LastLoggedIn != null)
        {
            var updateLastActivityDate = TimeSpan.FromMinutes(value: 2);
            var currentUtc = DateTimeOffset.UtcNow;
            var timeElapsed = currentUtc.Subtract(user.LastLoggedIn.Value);

            if (timeElapsed < updateLastActivityDate)
            {
                return;
            }
        }

        user.LastLoggedIn = DateTimeOffset.UtcNow;
        await _uow.SaveChangesAsync();
    }
}