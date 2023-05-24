using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Feliv_auth.Models
{
    public class ApplicationDbContext : IdentityDbContext<IdentityUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            SeedRoles(builder);
        }
        private void SeedRoles (ModelBuilder Builder)
        {
            Builder.Entity<IdentityRole>().HasData
                (
                    new IdentityRole() { Name = "Admin", ConcurrencyStamp = "1", NormalizedName = "Admin" },
                    new IdentityRole() { Name = "ApprovedStore", ConcurrencyStamp = "2", NormalizedName = "ApprovedStore" },
                    new IdentityRole() { Name = "PendingStore", ConcurrencyStamp = "3", NormalizedName = "PendingStore" },
                    new IdentityRole() { Name = "Customer", ConcurrencyStamp = "4", NormalizedName = "Customer" }
                );
        }
    }
}
