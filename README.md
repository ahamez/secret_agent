# SecretsWatcher

![Elixir CI](https://github.com/ahamez/secrets_watcher/workflows/Elixir%20CI/badge.svg) [![Coverage Status](https://coveralls.io/repos/github/ahamez/secrets_watcher/badge.svg?branch=master)](https://coveralls.io/github/ahamez/secrets_watcher?branch=master) [![Hex Docs](https://img.shields.io/badge/hex-docs-brightgreen.svg)](https://hexdocs.pm/secrets_watcher/) [![Hex.pm Version](http://img.shields.io/hexpm/v/secrets_watcher.svg)](https://hex.pm/packages/secrets_watcher) [![License](https://img.shields.io/hexpm/l/secrets_watcher.svg)](https://github.com/ahamez/secrets_watcher/blob/master/LICENSE)

An Elixir library to manage secrets, with the possibily to watch for their changes on filesystem.

Thereafter, _watched secrets_ are the secrets read from the filesystem, while _in-memory secrets_ are secrets which do not have a corresponding file.

As per the recommandation of the [EEF Security Workgroup](https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/sensitive_data), secrets are passed around as closures.


## Installation

```elixir
def deps do
  [
    {:secrets_watcher, "~> 0.6"}
  ]
end
```

## Usage

* Establish the list of secrets:
    ```elixir
    secrets =
      %{
        "aws-credentials.json" => [value: "super-secret"],
        "secret.txt" => [
          directory: "path/to/secrets/directory",
          callback: fn wrapped_secret-> do_something_with_secret(wrapped_secret) end
        ]
      }
    ```
    ℹ️ When using the `:directory` option, the name of the secret is the name of the file to watch in the directory. The secret will be loaded from the file upon startup. It this option is not set, the secret is considered to be an in-memory secret.

    ℹ️ The `:callback` option specifies a callback that will be invoked each time the watched secret has been updated on disk. Default to a function with no effect.

    ℹ️ The `:value` option specifies the initial value of the secret (default to `nil` for in-memory secrets). Supersed the value from the file if the `:directory` option has been set.


* Configure and add `secrets_watcher` to your supervision tree:
    ```elixir
    children =
      [
        {SecretsWatcher,
         [
           name: :secrets,
           secrets_watcher_config: [secrets: secrets]
         ]}
      ]

    opts = [strategy: :one_for_one, name: MyApp.Supervisor]
    Supervisor.start_link(children, opts)
    ```
    ℹ️ If you don't specify the `:name` option, `SecretsWatcher` will be used by default.

    👉 By default, `secrets_watcher` trim watched secrets read on disk with [`String.trim/1`](https://hexdocs.pm/elixir/1.13.2/String.html#trim/1). You can deactivate this behavior with the option `trim_secrets` set to `false`.

* Whenever you want to retrieve a secret, use `SecretsWatcher.get_secret/2`:
    ```elixir
    {:ok, wrapped_credentials} =
      SecretsWatcher.get_secret(:secrets, "aws-credentials.json")

    secret = wrapped_credentials.()
    ```

* You can manually update secrets with `SecretsWatcher.put_secret/3` and `SecretsWatcher.delete_secret/2`.
