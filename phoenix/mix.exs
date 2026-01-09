defmodule PhoenixBenchmark.MixProject do
  use Mix.Project

  def project do
    [
      app: :phoenix_benchmark,
      version: "1.0.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      escript: [main_module: PhoenixBenchmark.CLI]
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {PhoenixBenchmark.Application, []}
    ]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7"},
      {:plug_cowboy, "~> 2.6"},
      {:jason, "~> 1.4"},
      {:joken, "~> 2.6"},
      {:ex_doc, "~> 0.30", only: :dev}
    ]
  end
end
