defmodule Ash.Models.Product do
  @derive Jason.Encoder
  defstruct [:id, :name, :description, :userId, :price, :categoryId]

  def new(id, name, description, user_id, price, category_id) do
    %__MODULE__{
      id: id,
      name: name,
      description: description,
      userId: user_id,
      price: price,
      categoryId: category_id
    }
  end
end
