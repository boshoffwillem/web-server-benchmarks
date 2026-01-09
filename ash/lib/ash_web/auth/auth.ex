defmodule Ash.Auth do
  @signer Joken.Signer.create(
            "HS256",
            Base.decode16!(
              String.upcase("8d96c0a4544eb9dad7c6b2f1126f52d272d0d04074edbf0cb92f3a68fb")
            )
          )

  def generate_token(user) do
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1laWRlbnRpZmllciI6IjEiLCJuYW1lIjoiR2lhbmZyYW5jbyIsImVtYWlsIjoiZ2lhbmZyYW5jb0BlbWFpbC5jb20ifQ.signature"
  end

  def verify_token(_token) do
    {:ok, %{}}
  end
end
