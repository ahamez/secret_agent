# SecretAgent 🕵️

[![Elixir CI](https://github.com/ahamez/secret_agent/actions/workflows/elixir.yml/badge.svg)](https://github.com/ahamez/secret_agent/actions/workflows/elixir.yml) [![Coverage Status](https://coveralls.io/repos/github/ahamez/secret_agent/badge.svg?branch=master)](https://coveralls.io/github/ahamez/secret_agent?branch=master) [![Hex Docs](https://img.shields.io/badge/hex-docs-brightgreen.svg)](https://hexdocs.pm/secret_agent/) [![Hex.pm Version](http://img.shields.io/hexpm/v/secret_agent.svg)](https://hex.pm/packages/secret_agent) [![License](https://img.shields.io/hexpm/l/secret_agent.svg)](https://github.com/ahamez/secret_agent/blob/master/LICENSE)

An Elixir library to manage secrets, with the possibily to watch for their changes on filesystem.

Thereafter, _watched secrets_ are the secrets read from the filesystem, while _in-memory secrets_ are secrets which do not have a corresponding file.

As per the recommandation of the [EEF Security Workgroup](https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/sensitive_data), secrets are passed around as closures.


## Installation

```elixir
def deps do
  [
    {:secret_agent, "~> 0.8"}
  ]
end
```

## Usage

1. Establish the list of initial secrets:
    ```elixir
    secrets =
      %{
        "credentials" => [value: "super-secret"],
        "secret.txt" => [
          directory: "path/to/secrets/directory",
          init_callback: fn wrapped_secret-> do_something_with_secret(wrapped_secret) end,
          callback: fn wrapped_secret-> do_something_with_secret(wrapped_secret) end
        ],
        "sub/path/secret.txt" => [
          directory: "path/to/secrets/directory"
        ]
      }
    ```
    ℹ️ When using the `:directory` option, the name of the secret is the name of the file to watch in the directory. The secret will be loaded from the file upon startup. It this option is not set, the secret is considered to be an in-memory secret.

    ℹ️ The `:init_callback` option specifies a callback that will be invoked the first time the watched secret is read from disk. Default to a function with no effect.

    ℹ️ The `:callback` option specifies a callback that will be invoked each time the watched secret has been updated on disk. Default to a function with no effect.

    ℹ️ The `:value` option specifies the initial value of the secret (default to `nil` for in-memory secrets). Supersed the value from the file if the `:directory` option has been set.

    👉 You can add in-memory secrets dynamically with `SecretAgent.put_secret/3`.


* Configure and add `secret_agent` to your supervision tree:
    ```elixir
    children =
      [
        {SecretAgent,
         [
           name: :secrets,
           secret_agent_config: [secrets: secrets]
         ]}
      ]

    opts = [strategy: :one_for_one, name: MyApp.Supervisor]
    Supervisor.start_link(children, opts)
    ```
    ℹ️ If you don't specify the `:name` option, `SecretAgent` will be used by default.

    👉 By default, `secret_agent` trim watched secrets read on disk with [`String.trim/1`](https://hexdocs.pm/elixir/1.13.2/String.html#trim/1). You can deactivate this behavior with the option `trim_secrets` set to `false`.

* Whenever you want to retrieve a secret, use `SecretAgent.get_secret/2`:
    ```elixir
    {:ok, wrapped_credentials} = SecretAgent.get_secret(:secrets, "credentials")
    secret = wrapped_credentials.()
    ```

    👉 As a best practice, `secret_agent` erases secrets when accessing them. You can override this behavior with the option `erase: false`.


* You can manually update secrets with `SecretAgent.put_secret/3` and `SecretAgent.erase_secret/2`.
