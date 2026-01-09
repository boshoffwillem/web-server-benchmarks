defmodule PhoenixBenchmarkWeb.Router do
  require Logger

  def init(opts) do
    opts
  end

  def call(conn, _opts) do
    Logger.info("#{conn.method} #{conn.request_path}")

    # Parse JSON for all requests
    conn =
      Plug.Parsers.call(
        conn,
        Plug.Parsers.init(parsers: [:json], pass: ["application/json"], json_decoder: Jason)
      )

    case {conn.method, conn.request_path} do
      {"POST", "/api/v1/auth/login"} ->
        PhoenixBenchmarkWeb.AuthController.login(conn, conn.body_params)

      {"GET", "/api/v1/user/" <> id} ->
        conn = PhoenixBenchmarkWeb.AuthMiddleware.call(conn, [])

        if conn.state == :sent do
          conn
        else
          PhoenixBenchmarkWeb.UserController.get_user(conn, %{"id" => id})
        end

      {"GET", "/api/v1/product"} ->
        conn = PhoenixBenchmarkWeb.AuthMiddleware.call(conn, [])

        if conn.state == :sent do
          conn
        else
          PhoenixBenchmarkWeb.ProductController.get_all_products(conn, %{})
        end

      {"GET", "/api/v1/product/" <> id} ->
        conn = PhoenixBenchmarkWeb.AuthMiddleware.call(conn, [])

        if conn.state == :sent do
          conn
        else
          PhoenixBenchmarkWeb.ProductController.get_product(conn, %{"id" => id})
        end

      {"GET", "/api/v1/category/" <> id} ->
        conn = PhoenixBenchmarkWeb.AuthMiddleware.call(conn, [])

        if conn.state == :sent do
          conn
        else
          PhoenixBenchmarkWeb.CategoryController.get_category(conn, %{"id" => id})
        end

      _ ->
        conn
        |> Plug.Conn.send_resp(404, "Not Found")
    end
  end
end
