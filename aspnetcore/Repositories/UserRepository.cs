using local_ly_dotnet.Models;

namespace local_ly_dotnet.Repositories;

public class UserRepository
{
    private readonly List<User> _users =
    [
        new User
        {
            Id = "1",
            Name = "Gianfranco",
            Email = "gianfranco@email.com",
            Password = "Test123!",
        },
        new User
        {
            Id = "2",
            Name = "Gianfranco2",
            Email = "gianfranco@email.com",
            Password = "Test123!",
        },
        new User
        {
            Id = "3",
            Name = "Gianfranco3",
            Email = "gianfranco@email.com",
            Password = "Test123!",
        },
        new User
        {
            Id = "4",
            Name = "Gianfranco4",
            Email = "gianfranco@email.com",
            Password = "Test123!",
        },
        new User
        {
            Id = "5",
            Name = "Gianfranco5",
            Email = "gianfranco@email.com",
            Password = "Test123!",
        },
    ];

    public List<User> GetAllUsers() => _users;

    public User? GetUserById(string id) => _users.FirstOrDefault(u => u.Id == id);

    public User? GetUserByEmail(string email) => _users.FirstOrDefault(u => u.Email == email);
}
