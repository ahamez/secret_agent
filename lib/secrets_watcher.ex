defmodule SecretsWatcher do
  @moduledoc """
  This module provides the possibility to manage secrets and to watch for directory changes.

  It's aimed at managing secrets rotation (typically credentials written by Vault). Thus,
  it wraps secrets in closures to avoid leaking and use a constant-time comparison function
  to mitigate timing attacks.

  https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/sensitive_data
  https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/timing_attacks
  """

  @options_definition [
    secrets: [
      type: :any,
      required: true
    ],
    trim_secrets: [
      type: :boolean,
      required: false,
      default: true
    ]
  ]

  defmodule DefaultCallback do
    @moduledoc false
    def no_op(_wrapped_secret), do: nil
  end

  @secret_config_options [
    directory: nil,
    value: nil,
    callback: &DefaultCallback.no_op/1
  ]

  use GenServer

  alias SecretsWatcher.Telemetry

  defmodule State do
    @moduledoc false
    defstruct callbacks: %{},
              directory: nil,
              secrets: %{},
              task_supervisor_pid: nil,
              trim_secrets: true,
              watcher_pid: nil
  end

  def child_spec(opts) do
    %{
      id: opts[:name] || __MODULE__,
      start: {__MODULE__, :start_link, [opts]}
    }
  end

  @doc """
  Start `secrets_watcher` as a linked process.
  """
  def start_link(opts) do
    Process.flag(:sensitive, true)

    {secrets_opts, opts} = Keyword.pop!(opts, :secrets_watcher_config)

    with {:ok, secrets_opts} <- NimbleOptions.validate(secrets_opts, @options_definition) do
      server_opts = Keyword.take(opts, [:name])
      GenServer.start_link(__MODULE__, secrets_opts, server_opts)
    end
  end

  @doc """
  Return the secret value (a closure or `:erased`) corresponding to `secret_name`.
  """
  @spec get_secret(pid() | atom(), binary()) :: {:ok, function() | :erased} | {:error, term()}
  def get_secret(server, secret_name) when is_binary(secret_name) do
    GenServer.call(server, {:get_secret, secret_name})
  end

  @doc """
  Set the secret value of `secret_name` to `:erased`.

  If `secret_name` does not exist, nothing happen.
  """
  @spec erase_secret(pid() | atom(), binary()) :: :ok
  def erase_secret(server, secret_name) when is_binary(secret_name) do
    GenServer.call(server, {:erase_secret, secret_name})
  end

  @doc """
  Set the secret value (wrapped in a closure) of `secret_name`.

  If `secret_name` does not exist, it's added to existing secrets.
  """
  @spec put_secret(pid() | atom(), binary(), function()) :: :ok
  def put_secret(server, secret_name, wrapped_secret)
      when is_binary(secret_name) and is_function(wrapped_secret) do
    GenServer.call(server, {:put_secret, secret_name, wrapped_secret})
  end

  # -- GenServer

  @impl true
  def init(opts) do
    {secrets, opts} = Keyword.pop!(opts, :secrets)
    {trim_secrets, _opts} = Keyword.pop!(opts, :trim_secrets)

    with {:ok, secrets} <- validate_secrets_config(secrets),
         directories = get_directories(secrets),
         callbacks = get_callbacks(secrets),
         {:ok, task_supervisor_pid} <- Task.Supervisor.start_link(),
         {:ok, watcher_pid} <- SecretsWatcherFileSystem.start_link(dirs: directories),
         :ok <- SecretsWatcherFileSystem.subscribe(watcher_pid) do
      {
        :ok,
        %State{
          callbacks: callbacks,
          secrets: load_initial_secrets(secrets, trim_secrets),
          task_supervisor_pid: task_supervisor_pid,
          watcher_pid: watcher_pid,
          trim_secrets: trim_secrets
        }
      }
    else
      {:error, error} -> {:stop, error}
    end
  end

  @impl true
  def handle_info({:file_event, pid, {path, events}}, %State{watcher_pid: pid} = state) do
    Telemetry.event(:file_event, %{events: events, path: path})

    case load_updated_secret(state.secrets, events, path, state.trim_secrets) do
      :ignore ->
        {:noreply, state}

      {:changed, secret_name, wrapped_new_secret} ->
        Telemetry.event(:changed_secret, %{secret_name: secret_name})

        {
          :noreply,
          %{state | secrets: Map.put(state.secrets, secret_name, wrapped_new_secret)},
          {:continue, {:notify_secret_rotation, secret_name}}
        }
    end
  end

  @impl true
  def handle_info(_, state) do
    {:noreply, state}
  end

  @impl true
  def handle_continue({:notify_secret_rotation, secret_name}, state) do
    wrapped_secret_or_erased = Map.fetch!(state.secrets, secret_name)
    callback = Map.fetch!(state.callbacks, secret_name)

    {:ok, _task_pid} =
      Task.Supervisor.start_child(state.task_supervisor_pid, fn ->
        callback.(wrapped_secret_or_erased)
      end)

    {:noreply, state}
  end

  @impl true
  def handle_call({:get_secret, secret_name}, _from, %State{} = state) do
    response =
      case Map.get(state.secrets, secret_name) do
        nil -> {:error, :no_such_secret}
        wrapped_secret_or_erased -> {:ok, wrapped_secret_or_erased}
      end

    {:reply, response, state}
  end

  @impl true
  def handle_call({:erase_secret, secret_name}, _from, %State{} = state) do
    secrets = Map.replace(state.secrets, secret_name, :erased)

    {:reply, :ok, %State{state | secrets: secrets}}
  end

  @impl true
  def handle_call({:put_secret, secret_name, wrapped_secret}, _from, %State{} = state) do
    secrets = Map.put(state.secrets, secret_name, wrapped_secret)

    {:reply, :ok, %State{state | secrets: secrets}}
  end

  # -- Private

  defp load_initial_secrets(secrets, trim_secrets) do
    secrets
    |> Enum.map(fn {secret_name, secret_config} ->
      initial_value = Keyword.fetch!(secret_config, :value)
      directory = Keyword.fetch!(secret_config, :directory)

      value =
        cond do
          initial_value ->
            fn -> initial_value end

          directory ->
            Telemetry.event(:initial_loading, %{secret_name: secret_name, directory: directory})
            load_secret(directory, secret_name, trim_secrets)


          true ->
            fn -> nil end
        end

      {secret_name, value}
    end)
    |> Enum.into(%{})
  end

  defp load_updated_secret(secrets, events, path, trim_secret) do
    if contains_watched_events?(events) and is_file?(path) do
      {secret_name, wrapped_new_secret} = load_secret_from_path(path, trim_secret)
      wrapped_previous_secret = Map.get(secrets, secret_name)

      cond do
        # `secret_name` is not in `secrets`, we can ignore it.
        wrapped_previous_secret == nil ->
          :ignore

        wrapped_previous_secret == :erased ->
          {:changed, secret_name, wrapped_new_secret}

        SecretsWatcher.Compare.equal?(wrapped_previous_secret.(), wrapped_new_secret.()) ->
          :ignore

        true ->
          {:changed, secret_name, wrapped_new_secret}
      end
    else
      Telemetry.event(:unwatched_events, %{events: events, path: path})
      :ignore
    end
  end

  defp contains_watched_events?(events) do
    Enum.any?(events, fn
      :modified -> true
      :created -> true
      :renamed -> true
      :moved_to -> true
      _ -> false
    end)
  end

  defp is_file?(path) do
    File.exists?(path) and not File.dir?(path)
  end

  defp load_secret(dir, secret_name, trim_secret) do
    abs_path = Path.join(dir, secret_name)
    {^secret_name, wrapped_secret} = load_secret_from_path(abs_path, trim_secret)

    wrapped_secret
  end

  defp load_secret_from_path(path, trim_secret) do
    secret_name = Path.basename(path)

    case File.read(path) do
      {:ok, secret} ->
        secret =
          if trim_secret do
            String.trim(secret)
          else
            secret
          end

        {secret_name, fn -> secret end}

      {:error, _} ->
        {secret_name, fn -> nil end}
    end
  end

  defp validate_secrets_config(secrets) when is_map(secrets) do
    Enum.reduce_while(secrets, {:ok, %{}}, fn {secret_name, secret_config}, {:ok, acc} ->
      case Keyword.validate(secret_config, @secret_config_options) do
        {:ok, secret_config} ->
          {:cont, {:ok, Map.put(acc, secret_name, secret_config)}}

        {:error, invalid_options} ->
          {:halt, {:error, {:invalid_secret_config, secret_name, invalid_options}}}
      end
    end)
  end

  defp get_directories(secrets) when is_map(secrets) do
    Enum.reduce(secrets, [], fn {_secret_name, secret_config}, acc ->
      case Keyword.get(secret_config, :directory) do
        nil ->
          acc

        directory ->
          if directory in acc do
            acc
          else
            [directory | acc]
          end
      end
    end)
  end

  defp get_callbacks(secrets) when is_map(secrets) do
    Map.new(secrets, fn {secret_name, secret_config} ->
      {secret_name, Keyword.fetch!(secret_config, :callback)}
    end)
  end
end
