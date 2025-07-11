﻿using JwtAuth.Entities;
using Microsoft.EntityFrameworkCore;

namespace JwtAuth.Data
{
    public class UserDbContext : DbContext
    {
        public UserDbContext(DbContextOptions<UserDbContext> options) : base(options)
        {
        }

        // Create the tables
        public DbSet<User> Users { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<BlacklistedToken> BlacklistedTokens { get; set; }
        public DbSet<Video> Videos { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Check if we're using PostgreSQL
            bool isPostgres = Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL";

            modelBuilder.Entity<User>()
                .HasIndex(u => u.Id)
                .IsUnique();

            // Configure RefreshToken entity
            modelBuilder.Entity<RefreshToken>()
                .HasKey(t => t.Id);

            modelBuilder.Entity<RefreshToken>()
                .HasOne(t => t.User)
                .WithMany(u => u.RefreshTokens)
                .HasForeignKey(t => t.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // Configure Video entity
            modelBuilder.Entity<Video>()
                .HasKey(v => v.Id);

            modelBuilder.Entity<Video>()
                .Property(v => v.Format)
                .HasConversion<string>();

            // Configure foreign key relationship
            modelBuilder.Entity<Video>()
                .HasOne(v => v.User)
                .WithMany(u => u.Videos)
                .HasForeignKey(v => v.UserId)
                .IsRequired();

            // Configure BlacklistedToken entity
            modelBuilder.Entity<BlacklistedToken>()
                .HasKey(t => t.Jti);

            // Only add PostgreSQL-specific configurations if using PostgreSQL
            if (isPostgres)
            {
                // Add PostgreSQL-specific indexes for better performance
                modelBuilder.Entity<RefreshToken>()
                    .HasIndex(t => t.TokenHash)
                    .HasMethod("btree");

                modelBuilder.Entity<BlacklistedToken>()
                    .HasIndex(t => t.Jti)
                    .HasMethod("btree");
            }
        }
    }
}