

# SecretAgent 🕵️

[![Elixir CI](https://github.com/ahamez/secret_agent/actions/workflows/elixir.yml/badge.svg)](https://github.com/ahamez/secret_agent/actions/workflows/elixir.yml) [![Coverage Status](https://coveralls.io/repos/github/ahamez/secret_agent/badge.svg?branch=master)](https://coveralls.io/github/ahamez/secret_agent?branch=master) [![Hex Docs](https://img.shields.io/badge/hex-docs-brightgreen.svg)](https://hexdocs.pm/secret_agent/) [![Hex.pm Version](http://img.shields.io/hexpm/v/secret_agent.svg)](https://hex.pm/packages/secret_agent) [![License](https://img.shields.io/hexpm/l/secret_agent.svg)](https://github.com/ahamez/secret_agent/blob/master/LICENSE)

Una biblioteca de Elixir para gestionar secretos, con la posibilidad de observar cambios en ellos en el sistema de archivos.

Por lo tanto, los _secretos observados_ son los secretos leídos desde el sistema de archivos, mientras que los _secretos en memoria_ son aquellos que no tienen un archivo correspondiente.

Según la recomendación del [Grupo de Trabajo de Seguridad de EEF](https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/sensitive_data), los secretos se pasan como clausuras.


## Instalación

```elixir
def deps do
  [
    {:secret_agent, "~> 0.8"}
  ]
end
```

## Uso

1. Establece la lista de secretos iniciales:
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
    ℹ️ Al usar la opción `:directory`, el nombre del secreto es el nombre del archivo que se observará en el directorio. El secreto se cargará desde el archivo al iniciar. Si esta opción no se establece, el secreto se considera un secreto en memoria.

    ℹ️ La opción `:init_callback` especifica un callback que se invocará la primera vez que se lea el secreto observado desde el disco. El valor predeterminado es una función sin efecto.

    ℹ️ La opción `:callback` especifica un callback que se invocará cada vez que se actualice el secreto observado en el disco. El valor predeterminado es una función sin efecto.

    ℹ️ La opción `:value` especifica el valor inicial del secreto (por defecto `nil` para secretos en memoria). Anula el valor del archivo si se ha establecido la opción `:directory`.

    👉 Puedes agregar secretos en memoria dinámicamente con `SecretAgent.put_secret/3`.


* Configura y añade `secret_agent` a tu árbol de supervisión:
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
    ℹ️ Si no especificas la opción `:name`, se utilizará `SecretAgent` por defecto.

    👉 Por defecto, `secret_agent` recorta los secretos observados leídos desde el disco con [`String.trim/1`](https://hexdocs.pm/elixir/1.13.2/String.html#trim/1). Puedes desactivar este comportamiento con la opción `trim_secrets` establecida en `false`.

* Cada vez que quieras recuperar un secreto, usa `SecretAgent.get_secret/2`:
    ```elixir
    {:ok, wrapped_credentials} = SecretAgent.get_secret(:secrets, "credentials")
    secret = wrapped_credentials.()
    ```

    👉 Como buena práctica, `secret_agent` borra los secretos al acceder a ellos. Puedes anular este comportamiento con la opción `erase: false`.


* Puedes actualizar manualmente los secretos con `SecretAgent.put_secret/3` y `SecretAgent.erase_secret/2`.
