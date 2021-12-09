defmodule SecretsWatcher.MixProject do
  use Mix.Project

  def project do
    [
      app: :secrets_watcher,
      version: "0.1.1",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      name: "Secrets Watcher",
      source_url: "https://github.com/ahamez/secrets_watcher",
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
      {:file_system,
       git: "https://github.com/ahamez/file_system.git", branch: "no_tmp_dir", override: true},
      {:git_hooks, "~> 0.5", only: [:test, :dev], runtime: false},
      {:mix_test_watch, "~> 1.0", only: [:dev], runtime: false},
      {:nimble_options, "~> 0.3.0"}
    ]
  end

  defp description do
    """
    An Elixir library to watch secrets in a directory
    """
  end

  defp package do
    [
      name: :secrets_watcher,
      files: ["lib", "mix.exs", "README*", "LICENSE"],
      maintainers: ["Alexandre Hamez"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/ahamez/secrets_watcher"},
      exclude_patterns: [".DS_Store"]
    ]
  end
end
