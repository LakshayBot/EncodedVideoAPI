using EncodedVideoProject.Models;

namespace EncodedVideoProject.Services;

public interface IAuthService
{
    Task<AuthResponse> RegisterAsync(RegisterRequest request);
    Task<AuthResponse> LoginAsync(LoginRequest request);
    Task<User?> GetUserByIdAsync(Guid userId);
    string GenerateJwtToken(User user);
}
