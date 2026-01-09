defmodule Ash.Models.User do
  @derive {Jason.Encoder, only: [:id, :name, :email]}
  defstruct [:id, :name, :email, :password]

  def new(id, name, email, password) do
    %__MODULE__{id: id, name: name, email: email, password: password}
  end
end
