using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LungHealth.AuthorizationServer.OpenIddict.Data
{
    public class AuthorizationDbContext : IdentityDbContext<ApplicationUser>
    {
        public AuthorizationDbContext(DbContextOptions<AuthorizationDbContext> options)
            : base(options) { }
    }
}
