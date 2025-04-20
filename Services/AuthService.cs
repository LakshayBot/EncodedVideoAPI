using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using EncodedVideoProject.Data;
using EncodedVideoProject.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace EncodedVideoProject.Services;

public class AuthService : IAuthService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IConfiguration _configuration;

    public AuthService(ApplicationDbContext dbContext, IConfiguration configuration)
    {
        _dbContext = dbContext;
        _configuration = configuration;
    }

    public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
    {
        // Check if username already exists
        if (await _dbContext.Users.AnyAsync(u => u.Username == request.Username))
        {
            return new AuthResponse
            {
                Success = false,
                Message = "Username already exists."
            };
        }
        
        // Check if email already exists
        if (await _dbContext.Users.AnyAsync(u => u.Email == request.Email))
        {
            return new AuthResponse
            {
                Success = false,
                Message = "Email already exists."
            };
        }

        // Create new user with hashed password
        var user = new User
        {
            Username = request.Username,
            Email = request.Email,
            PasswordHash = HashPassword(request.Password),
            FirstName = request.FirstName,
            LastName = request.LastName
        };

        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();

        // Generate JWT token
        var token = GenerateJwtToken(user);

        return new AuthResponse
        {
            Success = true,
            Message = "Registration successful",
            Token = token,
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                CreatedAt = user.CreatedAt
            }
        };
    }

    public async Task<AuthResponse> LoginAsync(LoginRequest request)
    {
        // Find user by username
        var user = await _dbContext.Users.SingleOrDefaultAsync(u => u.Username == request.Username);

        // Check if user exists and password is correct
        if (user == null || !VerifyPassword(request.Password, user.PasswordHash))
        {
            return new AuthResponse
            {
                Success = false,
                Message = "Invalid username or password."
            };
        }

        // Update last login time
        user.LastLoginAt = DateTime.UtcNow;
        await _dbContext.SaveChangesAsync();

        // Generate JWT token
        var token = GenerateJwtToken(user);

        return new AuthResponse
        {
            Success = true,
            Message = "Login successful",
            Token = token,
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                CreatedAt = user.CreatedAt
            }
        };
    }

    public async Task<User?> GetUserByIdAsync(Guid userId)
    {
        return await _dbContext.Users.FindAsync(userId);
    }

    public string GenerateJwtToken(User user)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
            _configuration["JwtSettings:Key"] ?? throw new InvalidOperationException("JWT key is not configured")));
        
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Name, user.Username)
        };

        var token = new JwtSecurityToken(
            issuer: _configuration["JwtSettings:Issuer"],
            audience: _configuration["JwtSettings:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(12), // Token valid for 12 hours
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private string HashPassword(string password)
    {
        using var hmac = new HMACSHA512();
        var salt = hmac.Key;
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        
        var result = new byte[salt.Length + hash.Length];
        Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
        Buffer.BlockCopy(hash, 0, result, salt.Length, hash.Length);
        
        return Convert.ToBase64String(result);
    }

    private bool VerifyPassword(string password, string storedHash)
    {
        try // Add try-catch for potential Base64 or array index issues
        {
            var bytes = Convert.FromBase64String(storedHash);
            
            // Correct salt size for HMACSHA512 default key
            var salt = new byte[128]; 
            var hash = new byte[64]; // HMACSHA512 produces a 64-byte hash
            
            if (bytes.Length != salt.Length + hash.Length)
            {
                // Handle cases where the stored hash format is unexpected
                // Log this error
                return false; 
            }

            Buffer.BlockCopy(bytes, 0, salt, 0, salt.Length);
            // Correct the offset for copying the hash
            Buffer.BlockCopy(bytes, salt.Length, hash, 0, hash.Length); 
            
            using var hmac = new HMACSHA512(salt); // Use the extracted salt
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            
            // Compare the computed hash with the extracted hash
            return computedHash.SequenceEqual(hash); 
        }
        catch (FormatException)
        {
            // Handle invalid Base64 string
            // Log this error
            return false;
        }
        catch (ArgumentOutOfRangeException)
        {
            // Handle issues if Buffer.BlockCopy goes out of bounds (e.g., storedHash is too short)
            // Log this error
            return false;
        }
    }
}
