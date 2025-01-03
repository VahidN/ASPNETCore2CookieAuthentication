﻿namespace ASPNETCore2CookieAuthentication.DomainClasses;

public class User
{
    public User() => UserRoles = [];

    public int Id { get; set; }

    public required string Username { get; set; }

    public required string Password { get; set; }

    public string? DisplayName { get; set; }

    public bool IsActive { get; set; }

    public DateTimeOffset? LastLoggedIn { get; set; }

    /// <summary>
    ///     every time the user changes his Password,
    ///     or an admin changes his Roles or stat/IsActive,
    ///     create a new `SerialNumber` GUID and store it in the DB.
    /// </summary>
    public string? SerialNumber { get; set; }

    public virtual ICollection<UserRole> UserRoles { get; set; }
}