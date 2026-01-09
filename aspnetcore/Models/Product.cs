namespace local_ly_dotnet.Models;

public class Product
{
    public required string Id { get; set; }
    public required string Name { get; set; }
    public required string Description { get; set; }
    public required string UserId { get; set; }
    public required decimal Price { get; set; }
    public required string CategoryId { get; set; }
}