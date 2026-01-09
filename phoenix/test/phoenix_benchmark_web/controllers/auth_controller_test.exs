defmodule PhoenixBenchmarkWeb.AuthControllerTest do
  use ExUnit.Case, async: true

  import Plug.Test
  alias Plug.Conn
  alias PhoenixBenchmarkWeb.Router

  defp create_conn(method, path, body \\ nil) do
    conn =
      conn(method, path, body)
      |> Conn.put_req_header("content-type", "application/json")

    Router.call(conn, Router.init(%{}))
  end

  test "POST /api/v1/auth/login with valid credentials returns a token" do
    conn = create_conn("POST", "/api/v1/auth/login", ~s'{"email": "gianfranco@email.com", "password": "Test123!"}')

    assert conn.state == :sent
    assert conn.status == 200

    body = Jason.decode!(conn.resp_body)
    assert Map.has_key?(body, "token")
  end

  test "POST /api/v1/auth/login with invalid credentials returns unauthorized" do
    conn = create_conn("POST", "/api/v1/auth/login", ~s'{"email": "test@example.com", "password": "wrongpassword"}')

    assert conn.state == :sent
    assert conn.status == 401
  end
end
