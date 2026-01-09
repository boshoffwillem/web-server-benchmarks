defmodule AshWeb.CategoryController do
  use AshWeb, :controller
  alias Ash.Repositories.CategoryRepository

  def index(conn, _params) do
    case CategoryRepository.get_all_categories() do
      nil ->
        send_json(conn, 404, %{"error" => "Categories not found"})

      categories ->
        send_json(conn, 200, %{"categories" => categories})
    end
  end

  def show(conn, %{"id" => id}) do
    case CategoryRepository.get_category_by_id(id) do
      nil ->
        send_json(conn, 404, %{"error" => "Category not found"})

      category ->
        send_json(conn, 200, %{"category" => category})
    end
  end

  defp send_json(conn, status, data) do
    conn
    |> put_status(status)
    |> put_resp_header("content-type", "application/json")
    |> send_resp(status, Jason.encode!(data))
  end
end
