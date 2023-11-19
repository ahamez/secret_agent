defmodule SecretAgent.MixProject do
  use Mix.Project

  def project do
    [
      app: :secret_agent,
      version: "0.8.3",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      name: "Secret Agent",
      source_url: "https://github.com/ahamez/secret_agent",
      description: description(),
      package: package(),
      dialyzer: [plt_local_path: "priv/plts"]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:credo, "~> 1.6", only: [:test, :dev], runtime: false},
      {:dialyxir, "~> 1.0", only: [:test, :dev], runtime: false},
      {:excoveralls, "~> 0.13", only: [:test], runtime: false},
      {:ex_doc, "~> 0.22", only: [:dev], runtime: false},
      {:file_system, "~> 1.0", override: true},
      {:git_hooks, "~> 0.5", only: [:test, :dev], runtime: false},
      {:mix_test_watch, "~> 1.0", only: [:dev], runtime: false},
      {:nimble_options, ">= 0.0.0"},
      {:telemetry, "~> 1.0"}
    ]
  end

  defp description do
    """
    An Elixir library to manage secrets
    """
  end

  defp package do
    [
      name: :secret_agent,
      files: ["lib", "mix.exs", "README*", "LICENSE"],
      maintainers: ["Alexandre Hamez"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/ahamez/secret_agent"},
      exclude_patterns: [".DS_Store"]
    ]
  end
end
