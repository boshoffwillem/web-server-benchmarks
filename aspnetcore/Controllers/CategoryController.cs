using local_ly_dotnet.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace local_ly_dotnet.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
[Authorize]
public class CategoryController : ControllerBase
{
    private readonly CategoryRepository _categoryRepository;

    public CategoryController(CategoryRepository categoryRepository)
    {
        _categoryRepository = categoryRepository;
    }

    [HttpGet("{id}")]
    public IActionResult GetCategoryById(string id)
    {
        var category = _categoryRepository.GetCategoryById(id);

        if (category == null)
        {
            return NotFound();
        }

        return Ok(new { category });
    }
}
