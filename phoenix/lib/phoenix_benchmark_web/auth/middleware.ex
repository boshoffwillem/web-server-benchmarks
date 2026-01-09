defmodule PhoenixBenchmarkWeb.AuthMiddleware do
  import Plug.Conn

  def init(opts) do
    opts
  end

  def call(conn, _opts) do
    case get_bearer_token(conn) do
      {:ok, token} ->
        case PhoenixBenchmark.Auth.verify_token(token) do
          {:ok, _claims} -> conn
          {:error, _} -> halt_unauthorized(conn)
        end

      :error ->
        halt_unauthorized(conn)
    end
  end

  defp get_bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      [header] ->
        case String.split(header, " ", parts: 2) do
          ["Bearer", token] -> {:ok, token}
          _ -> :error
        end

      _ ->
        :error
    end
  end

  defp halt_unauthorized(conn) do
    conn
    |> put_status(401)
    |> Plug.Conn.send_resp(401, Jason.encode!(%{"error" => "Unauthorized"}))
    |> halt()
  end
end
