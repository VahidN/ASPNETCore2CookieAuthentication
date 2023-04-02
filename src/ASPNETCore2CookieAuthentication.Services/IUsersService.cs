using ASPNETCore2CookieAuthentication.DomainClasses;

namespace ASPNETCore2CookieAuthentication.Services;

public interface IUsersService
{
    Task<string?> GetSerialNumberAsync(int userId);
    Task<User?> FindUserAsync(string username, string password);
    ValueTask<User?> FindUserAsync(int userId);
    Task UpdateUserLastActivityDateAsync(int userId);
}