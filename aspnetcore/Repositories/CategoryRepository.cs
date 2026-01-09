using local_ly_dotnet.Models;

namespace local_ly_dotnet.Repositories;

public class CategoryRepository
{
    private readonly List<Category> _categories =
    [
        new Category { Id = "1", Name = "Dairy" },
        new Category { Id = "2", Name = "Fruit" },
        new Category { Id = "3", Name = "Vegetables" },
        new Category { Id = "4", Name = "Bakery" },
        new Category { Id = "5", Name = "Meat" },
    ];

    public List<Category> GetAllCategories() => _categories;

    public Category? GetCategoryById(string id) => _categories.FirstOrDefault(c => c.Id == id);
}
