using local_ly_dotnet.Models;

namespace local_ly_dotnet.Repositories;

public class ProductRepository
{
    private readonly List<Product> _products;

    public ProductRepository()
    {
        _products = [];
        for (int i = 1; i <= 10_000; i++)
        {
            _products.Add(
                new Product
                {
                    Id = i.ToString(),
                    Name = $"Product {i}",
                    Description = $"Description for product {i}",
                    UserId = ((i % 5) + 1).ToString(),
                    Price = i * 1.5m,
                    CategoryId = ((i % 5) + 1).ToString(),
                }
            );
        }
    }

    public List<Product> GetAllProducts() => _products;

    public Product? GetProductById(string id) => _products.FirstOrDefault(p => p.Id == id);
}
