using local_ly_dotnet.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace local_ly_dotnet.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
[Authorize]
public class UserController : ControllerBase
{
    private readonly UserRepository _userRepository;

    public UserController(UserRepository userRepository)
    {
        _userRepository = userRepository;
    }

    [HttpGet("{id}")]
    public IActionResult GetUserById(string id)
    {
        var user = _userRepository.GetUserById(id);

        if (user == null)
        {
            return NotFound();
        }

        return Ok(new { user });
    }
}
