using System.Text.Encodings.Web;
using ASPNETCore2CookieAuthentication.DataLayer.Context;
using ASPNETCore2CookieAuthentication.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
ConfigureLogging(builder.Logging, builder.Environment, builder.Configuration);
ConfigureServices(builder.Services, builder.Configuration);
var webApp = builder.Build();
ConfigureMiddlewares(webApp, webApp.Environment);
ConfigureEndpoints(webApp, webApp.Environment);
ConfigureDatabase(webApp);
await webApp.RunAsync();

void ConfigureServices(IServiceCollection services, IConfiguration configuration)
{
    services.AddHttpContextAccessor();
    services.AddScoped<IUnitOfWork, ApplicationDbContext>();
    services.AddScoped<IDeviceDetectionService, DeviceDetectionService>();
    services.AddScoped<IUsersService, UsersService>();
    services.AddScoped<IRolesService, RolesService>();
    services.AddScoped<ISecurityService, SecurityService>();
    services.AddScoped<ICookieValidatorService, CookieValidatorService>();
    services.AddScoped<IDbInitializerService, DbInitializerService>();

    services.AddDbContext<ApplicationDbContext>(options =>
    {
        var connectionString = configuration.GetConnectionString(name: "DefaultConnection");

        options.UseSqlServer(connectionString, serverDbContextOptionsBuilder =>
        {
            var minutes = (int)TimeSpan.FromMinutes(value: 3).TotalSeconds;
            serverDbContextOptionsBuilder.CommandTimeout(minutes);
            serverDbContextOptionsBuilder.EnableRetryOnFailure();
        });
    });

    // Only needed for custom roles.
    services.AddAuthorization(options =>
    {
        options.AddPolicy(CustomRoles.Admin, policy => policy.RequireRole(CustomRoles.Admin));
        options.AddPolicy(CustomRoles.User, policy => policy.RequireRole(CustomRoles.User));
    });

    // Needed for cookie auth.
    services.AddAuthentication(options =>
        {
            options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        })
        .AddCookie(options =>
        {
            options.SlidingExpiration = false;
            options.LoginPath = "/api/account/login";
            options.LogoutPath = "/api/account/logout";

            //options.AccessDeniedPath = new PathString("/Home/Forbidden/");
            options.Cookie.Name = ".my.app1.cookie";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            options.Cookie.SameSite = SameSiteMode.Lax;

            options.Events = new CookieAuthenticationEvents
            {
                OnValidatePrincipal = context =>
                {
                    var cookieValidatorService = context.HttpContext.RequestServices
                        .GetRequiredService<ICookieValidatorService>();

                    return cookieValidatorService.ValidateAsync(context);
                }
            };
        });

    services.AddCors(options =>
    {
        options.AddPolicy(name: "CorsPolicy", builderPolicy => builderPolicy
            .WithOrigins("http://localhost:4200") //Note:  The URL must be specified without a trailing slash (/).
            .AllowAnyMethod()
            .AllowAnyHeader()
            .SetIsOriginAllowed(_ => true)
            .AllowCredentials());
    });

    services.AddControllersWithViews();
}

void ConfigureLogging(ILoggingBuilder logging, IHostEnvironment env, IConfiguration configuration)
{
    logging.ClearProviders();

    logging.AddDebug();

    if (env.IsDevelopment())
    {
        logging.AddConsole();
    }

    logging.AddConfiguration(configuration.GetSection(key: "Logging"));
}

void ConfigureMiddlewares(IApplicationBuilder app, IHostEnvironment env)
{
    if (!env.IsDevelopment())
    {
        app.UseHsts();
    }

    app.UseHttpsRedirection();

    // Application level exception handler here - this is just a place holder
    app.UseExceptionHandler(errorApp => errorApp.Run(async context =>
    {
        context.Response.StatusCode = 500;
        context.Response.ContentType = "text/html";
        await context.Response.WriteAsync(text: "<html><body>\r\n");

        await context.Response.WriteAsync(
            text: "We're sorry, we encountered an un-expected issue with your application.<br>\r\n");

        // Capture the exception
        var error = context.Features.Get<IExceptionHandlerFeature>();

        if (error != null)
        {
            // This error would not normally be exposed to the client
            await context.Response.WriteAsync("<br>Error: " + HtmlEncoder.Default.Encode(error.Error.Message) +
                                              "<br>\r\n");
        }

        await context.Response.WriteAsync(text: "<br><a href=\"/\">Home</a><br>\r\n");
        await context.Response.WriteAsync(text: "</body></html>\r\n");
        await context.Response.WriteAsync(new string(c: ' ', count: 512)); // Padding for IE
    }));

    app.UseStatusCodePages();

    app.UseStaticFiles();

    app.UseRouting();

    app.UseAuthentication();

    app.UseCors(policyName: "CorsPolicy");

    app.UseAuthorization();
}

void ConfigureEndpoints(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");
    });

    // catch-all handler for HTML5 client routes - serve index.html
    app.Run(async context =>
    {
        context.Response.ContentType = "text/html";
        await context.Response.SendFileAsync(Path.Combine(env.WebRootPath, path2: "index.html"));
    });
}

void ConfigureDatabase(IApplicationBuilder app)
{
    var scopeFactory = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>();
    using var scope = scopeFactory.CreateScope();
    var dbInitializer = scope.ServiceProvider.GetRequiredService<IDbInitializerService>();
    dbInitializer.Initialize();
    dbInitializer.SeedData();
}