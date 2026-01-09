using local_ly_dotnet.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace local_ly_dotnet.Controllers;

[ApiController]
[Route("api/v1/product")]
[Authorize]
public class ProductController : ControllerBase
{
    private readonly ProductRepository _productRepository;

    public ProductController(ProductRepository productRepository)
    {
        _productRepository = productRepository;
    }

    [HttpGet]
    public IActionResult GetAllProducts()
    {
        var products = _productRepository.GetAllProducts();
        return Ok(new { products });
    }

    [HttpGet("{id}")]
    public IActionResult GetProductById(string id)
    {
        var product = _productRepository.GetProductById(id);

        if (product == null)
        {
            return NotFound();
        }

        return Ok(new { product });
    }
}
