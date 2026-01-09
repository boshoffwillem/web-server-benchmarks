defmodule AshWeb.ProductController do
  use AshWeb, :controller
  alias Ash.Repositories.ProductRepository

  def index(conn, _params) do
    products = ProductRepository.get_all_products()
    send_json(conn, 200, %{"products" => products})
  end

  def show(conn, %{"id" => id}) do
    case ProductRepository.get_product_by_id(id) do
      nil ->
        send_json(conn, 404, %{"error" => "Product not found"})

      product ->
        send_json(conn, 200, %{"product" => product})
    end
  end

  defp send_json(conn, status, data) do
    conn
    |> put_status(status)
    |> put_resp_header("content-type", "application/json")
    |> send_resp(status, Jason.encode!(data))
  end
end
