defmodule Ash.Repositories.UserRepository do
  alias Ash.Models.User

  @users [
    User.new("1", "Gianfranco", "gianfranco@email.com", "Test123!"),
    User.new("2", "Gianfranco2", "gianfranco@email.com", "Test123!"),
    User.new("3", "Gianfranco3", "gianfranco@email.com", "Test123!"),
    User.new("4", "Gianfranco4", "gianfranco@email.com", "Test123!"),
    User.new("5", "Gianfranco5", "gianfranco@email.com", "Test123!")
  ]

  def get_all_users do
    @users
  end

  def get_user_by_id(id) do
    Enum.find(@users, fn user -> user.id == id end)
  end

  def get_user_by_email(email) do
    Enum.find(@users, fn user -> user.email == email end)
  end
end
