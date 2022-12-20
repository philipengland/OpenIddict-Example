using LungHealth.AuthorizationServer.OpenIddict.Data;
using LungHealth.AuthorizationServer.OpenIddict.Handlers;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AuthorizationDbContext>(options =>
{
    // Configure the context to use Microsoft SQL Server.
   options.UseSqlServer(builder.Configuration.GetConnectionString("AuthorizationDbContext"));
 //   options.UseSqlServer(builder.Configuration.GetConnectionString("AuthorizationDbContext"));
 //    Register the entity sets needed by OpenIddict
    options.UseOpenIddict();
});

// Register the Identity services.
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<AuthorizationDbContext>()
            .AddDefaultTokenProviders();
 //   .AddDefaultUI();

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        // Configure OpenIddict to use the EF Core stores/models.
        options.UseEntityFrameworkCore()
            .UseDbContext<AuthorizationDbContext>();
    })
    .AddServer(options =>
    {
        options
        .AllowAuthorizationCodeFlow()
        .RequireProofKeyForCodeExchange()
        .AllowClientCredentialsFlow()
        .AllowRefreshTokenFlow();

        options
            .SetUserinfoEndpointUris("/connect/userinfo")
            .SetAuthorizationEndpointUris("/connect/authorize")
            .SetTokenEndpointUris("/connect/token");

        // Encryption and signing of tokens - DEVELOPMENT ONLY
        options
            .AddEphemeralEncryptionKey()
            .AddEphemeralSigningKey();

        // Register scopes (permissions)
        // Mark the "email", "profile" and "roles" scopes as supported scopes.
        options.RegisterScopes("api", Scopes.Email, Scopes.Profile, Scopes.Roles);

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options
            .UseAspNetCore()
            .EnableTokenEndpointPassthrough()
            .EnableAuthorizationEndpointPassthrough();
    });

builder.Services.AddHostedService<TestData>();

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
       .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
       {
           options.LoginPath = "/account/login";
       });

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
});

app.Run();
