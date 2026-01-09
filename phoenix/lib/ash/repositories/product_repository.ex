defmodule Ash.Repositories.ProductRepository do
  alias Ash.Models.Product

  @products 1..10000
            |> Enum.map(fn i ->
              user_id = rem(i - 1, 5) + 1
              category_id = rem(i - 1, 5) + 1

              Product.new(
                Integer.to_string(i),
                "Product #{i}",
                "Description for product #{i}",
                Integer.to_string(user_id),
                i * 1.5,
                Integer.to_string(category_id)
              )
            end)
            |> Enum.to_list()

  def get_all_products do
    @products
  end

  def get_product_by_id(id) do
    Enum.find(@products, fn product -> product.id == id end)
  end
end
