defmodule Ash.Repositories.CategoryRepository do
  alias Ash.Models.Category

  @categories [
    Category.new("1", "Dairy"),
    Category.new("2", "Fruit"),
    Category.new("3", "Vegetables"),
    Category.new("4", "Bakery"),
    Category.new("5", "Meat")
  ]

  def get_all_categories do
    @categories
  end

  def get_category_by_id(id) do
    Enum.find(@categories, fn category -> category.id == id end)
  end
end
