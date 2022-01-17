# SecretsWatcher

![Elixir CI](https://github.com/ahamez/secrets_watcher/workflows/Elixir%20CI/badge.svg) [![Coverage Status](https://coveralls.io/repos/github/ahamez/secrets_watcher/badge.svg?branch=master)](https://coveralls.io/github/ahamez/secrets_watcher?branch=master) [![Hex Docs](https://img.shields.io/badge/hex-docs-brightgreen.svg)](https://hexdocs.pm/secrets_watcher/) [![Hex.pm Version](http://img.shields.io/hexpm/v/secrets_watcher.svg)](https://hex.pm/packages/secrets_watcher) [![License](https://img.shields.io/hexpm/l/secrets_watcher.svg)](https://github.com/ahamez/secrets_watcher/blob/master/LICENSE)

An Elixir library to watch secrets changes in a given directory.

## Installation

```elixir
def deps do
  [
    {:secrets_watcher, "~> 0.5"}
  ]
end
```

## Usage

* Establish the list of secrets you want to watch in a directory:
    ```elixir
        secrets =
        [
          "aws-credentials.json",
          {"secret.txt", fn wrapped_secret-> do_something_with_secret(wrapped_secret) end}
        ]
    ```
    ℹ️ Note that you actually use the filename of the secret to watch in a directory.

    ℹ️ The form `{"secret_filename", callback}` registers a callback which is called each time a secret has changed on disk.

* Configure and add `secrets_watcher` to your supervision tree:
    ```elixir
    children =
      [
        {SecretsWatcher,
         [
           name: :secrets,
           secrets_watcher_config: [directory: path_to_secrets_directory, secrets: secrets]
         ]}
      ]

    opts = [strategy: :one_for_one, name: MyApp.Supervisor]
    Supervisor.start_link(children, opts)
    ```
    ℹ️ If you don't specify the `:name` option, `SecretsWatcher` will be used by default.

    👉 By default, `secrets_watcher` trim secrets with [`String.trim/1`](https://hexdocs.pm/elixir/1.13.2/String.html#trim/1). You can deactivate this behavior with the option `trim_secrets`set to `false`.

* Whenever you want to retrieve a secret, use `SecretsWatcher.get_wrapped_secret/2`:
    ```elixir
    {:ok, wrapped_credentials} =
      SecretsWatcher.get_wrapped_secret(:secrets, "aws-credentials.json")

    secret = wrapped_credentials.()
    ```
