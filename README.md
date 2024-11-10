Cookie Authentication without ASP.NET Core Identity 8x
===========

<p>
  <a href="https://github.com/VahidN/ASPNETCore2CookieAuthentication">
     <img alt="GitHub Actions status" src="https://github.com/VahidN/ASPNETCore2CookieAuthentication/workflows/.NET%20Core%20Build/badge.svg">
  </a>
</p>


![cookieauth](/src/ASPNETCore2CookieAuthentication.WebApp/wwwroot/images/cookieauth.png)

A cookie based authentication sample for ASP.NET Core 8x without using the Identity system. It includes:

- Users and Roles tables with a many-to-may relationship.
- A separated EF Core data layer with enabled migrations.
- An EF Core 8x based service layer.
- A Db initializer to seed the default database values.
- An account controller with cookie and DB based login and logout capabilities.
- 2 sample API controllers to show how user-roles can be applied and used.
- A cookie validator service to show how to react to the server side changes to a user's info immediately.