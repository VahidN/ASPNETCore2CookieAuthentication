dotnet tool update --global dotnet-ef --version 9.0.0
dotnet tool restore
dotnet build
dotnet ef --startup-project ../ASPNETCore2CookieAuthentication.WebApp/ database update
pause