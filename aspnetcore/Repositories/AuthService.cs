using local_ly_dotnet.Models;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace local_ly_dotnet.Repositories;

public class AuthService
{
    private readonly UserRepository _userRepository;

    public AuthService(UserRepository userRepository)
    {
        _userRepository = userRepository;
    }

    public User? FindByEmailAndPassword(string requestEmail, string requestPassword)
    {
        var user = _userRepository.GetUserByEmail(requestEmail);
        if (user != null && user.Password == requestPassword)
        {
            return user;
        }
        return null;
    }

    public string GenerateToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = "8d96c0a4544eb9dad7c6b2f1126f52d272d0d04074edbf0cb92f3a68fb"u8.ToArray();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["nameidentifier"] = user.Id,
                ["name"] = user.Name,
                ["email"] = user.Email,
            },
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
