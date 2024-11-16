namespace ASPNETCore2CookieAuthentication.DomainClasses;

public class Role
{
    public Role() => UserRoles = [];

    public int Id { get; set; }

    public required string Name { get; set; }

    public virtual ICollection<UserRole> UserRoles { get; set; }
}