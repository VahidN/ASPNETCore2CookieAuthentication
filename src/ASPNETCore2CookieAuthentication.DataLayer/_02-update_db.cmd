dotnet tool update --global dotnet-ef --version 8.0.10
dotnet tool restore
dotnet build
dotnet ef --startup-project ../ASPNETCore2CookieAuthentication.WebApp/ database update
pause