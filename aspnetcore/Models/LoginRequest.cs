namespace local_ly_dotnet.Models;

public class LoginRequest
{
    public required string Email { get; set; }
    public required string Password { get; set; }
}