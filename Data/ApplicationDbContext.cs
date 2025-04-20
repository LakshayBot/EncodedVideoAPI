using Microsoft.EntityFrameworkCore;
using EncodedVideoProject.Models;

namespace EncodedVideoProject.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
    
    public DbSet<EncryptedFile> EncryptedFiles { get; set; }
    public DbSet<EncryptionKey> EncryptionKeys { get; set; }
    public DbSet<User> Users { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        modelBuilder.Entity<EncryptedFile>()
            .HasOne(e => e.EncryptionKey)
            .WithMany(k => k.EncryptedFiles)
            .HasForeignKey(e => e.KeyId)
            .OnDelete(DeleteBehavior.Restrict);
            
        modelBuilder.Entity<EncryptedFile>()
            .Property(e => e.CreatedAt)
            .HasDefaultValueSql("CURRENT_TIMESTAMP");
            
        modelBuilder.Entity<EncryptionKey>()
            .Property(k => k.CreatedAt)
            .HasDefaultValueSql("CURRENT_TIMESTAMP");
            
        // Configure User entity relationships
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Username)
            .IsUnique();
            
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Email)
            .IsUnique();
            
        // Configure the relationship between User and EncryptedFile
        modelBuilder.Entity<EncryptedFile>()
            .HasOne(e => e.User)
            .WithMany(u => u.EncryptedFiles)
            .HasForeignKey(e => e.UserId)
            .IsRequired(false)
            .OnDelete(DeleteBehavior.SetNull);
    }
}