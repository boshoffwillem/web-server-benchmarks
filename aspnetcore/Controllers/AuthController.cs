using local_ly_dotnet.Models;
using local_ly_dotnet.Repositories;
using Microsoft.AspNetCore.Mvc;

namespace local_ly_dotnet.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AuthService _authService;

    public AuthController(AuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var user = _authService.FindByEmailAndPassword(request.Email, request.Password);
        if (user == null)
        {
            return Unauthorized();
        }

        var token = _authService.GenerateToken(user);
        return Ok(new LoginResponse { Token = token });
    }
}
