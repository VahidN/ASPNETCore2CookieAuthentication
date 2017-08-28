using System;
using System.IO;
using System.Text.Encodings.Web;
using ASPNETCore2CookieAuthentication.DataLayer.Context;
using ASPNETCore2CookieAuthentication.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ASPNETCore2CookieAuthentication.WebApp
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddScoped<IUnitOfWork, ApplicationDbContext>();
            services.AddScoped<IUsersService, UsersService>();
            services.AddScoped<IRolesService, RolesService>();
            services.AddScoped<ISecurityService, SecurityService>();
            services.AddScoped<ICookieValidatorService, CookieValidatorService>();
            services.AddScoped<IDbInitializerService, DbInitializerService>();

            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection"),
                    serverDbContextOptionsBuilder =>
                        {
                            var minutes = (int)TimeSpan.FromMinutes(3).TotalSeconds;
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
            services
                .AddAuthentication(options =>
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
                            var cookieValidatorService = context.HttpContext.RequestServices.GetRequiredService<ICookieValidatorService>();
                            return cookieValidatorService.ValidateAsync(context);
                        }
                    };
                });


            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy",
                    builder => builder
                        .AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader()
                        .AllowCredentials());
            });

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                // Application level exception handler here - this is just a place holder
                app.UseExceptionHandler(errorApp => errorApp.Run(async (context) =>
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync("<html><body>\r\n");
                    await context.Response.WriteAsync(
                            "We're sorry, we encountered an un-expected issue with your application.<br>\r\n");

                    // Capture the exception
                    var error = context.Features.Get<IExceptionHandlerFeature>();
                    if (error != null)
                    {
                        // This error would not normally be exposed to the client
                        await context.Response.WriteAsync("<br>Error: " +
                                        HtmlEncoder.Default.Encode(error.Error.Message) +
                                        "<br>\r\n");
                    }
                    await context.Response.WriteAsync("<br><a href=\"/\">Home</a><br>\r\n");
                    await context.Response.WriteAsync("</body></html>\r\n");
                    await context.Response.WriteAsync(new string(' ', 512)); // Padding for IE
                }));
            }

            app.UseAuthentication();

            var scopeFactory = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>();
            using (var scope = scopeFactory.CreateScope())
            {
                var dbInitializer = scope.ServiceProvider.GetService<IDbInitializerService>();
                dbInitializer.Initialize();
                dbInitializer.SeedData();
            }

            app.UseStatusCodePages();
            app.UseDefaultFiles(); // so index.html is not required
            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });

            // catch-all handler for HTML5 client routes - serve index.html
            app.Run(async context =>
            {
                context.Response.ContentType = "text/html";
                await context.Response.SendFileAsync(Path.Combine(env.WebRootPath, "index.html"));
            });
        }
    }
}
