using local_ly_dotnet.Repositories;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Register repositories
builder.Services.AddSingleton<UserRepository>();
builder.Services.AddSingleton<CategoryRepository>();
builder.Services.AddSingleton<ProductRepository>();

// Register services
builder.Services.AddSingleton<AuthService>();

// Configure JWT authentication
builder
    .Services.AddAuthentication("Bearer")
    .AddJwtBearer(
        "Bearer",
        options =>
        {
            options.TokenValidationParameters =
                new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
                        "8d96c0a4544eb9dad7c6b2f1126f52d272d0d04074edbf0cb92f3a68fb"u8.ToArray()
                    ),
                };
        }
    );

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
