defmodule SecretsWatcher do
  @moduledoc """
  This module provides the possibility to watch for a directory changes and to have callbacks called
  upon file modification.

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

  def start_link(opts) do
    Process.flag(:sensitive, true)

    {secrets_opts, opts} = Keyword.pop!(opts, :secrets_watcher_config)

    with {:ok, secrets_opts} <- NimbleOptions.validate(secrets_opts, @options_definition) do
      server_opts = Keyword.take(opts, [:name])
      GenServer.start_link(__MODULE__, secrets_opts, server_opts)
    end
  end

  @doc """
  Return the secret value (wrapped in a closure) corresponding to `secret_name`.
  """
  @spec get_wrapped_secret(pid() | atom(), binary()) :: {:ok, function()} | {:error, term()}
  def get_wrapped_secret(server, secret_name) when is_binary(secret_name) do
    GenServer.call(server, {:get_wrapped_secret, secret_name})
  end

  @doc """
  Delete the secret value corresponding to `secret_name`.

  If `secret_name` does not exist, nothing happen.
  """
  @spec delete_wrapped_secret(pid() | atom(), binary()) :: :ok
  def delete_wrapped_secret(server, secret_name) when is_binary(secret_name) do
    GenServer.call(server, {:delete_wrapped_secret, secret_name})
  end

  @doc """
  Set the secret value (wrapped in a closure) of `secret_name`.

  If `secret_name` does not exist, it's added to existing secrets.
  """
  @spec put_wrapped_secret(pid() | atom(), binary(), function()) :: :ok
  def put_wrapped_secret(server, secret_name, wrapped_secret)
      when is_binary(secret_name) and is_function(wrapped_secret) do
    GenServer.call(server, {:put_wrapped_secret, secret_name, wrapped_secret})
  end

  # -- GenServer

  @impl true
  def init(opts) do
    {secrets, opts} = Keyword.pop!(opts, :secrets)
    {trim_secrets, _opts} = Keyword.pop!(opts, :trim_secrets)

    with {:ok, directories} <- get_directories(secrets),
         callbacks = make_callbacks(secrets),
         {:ok, task_supervisor_pid} <- Task.Supervisor.start_link(),
         {:ok, watcher_pid} <- SecretsWatcherFileSystem.start_link(dirs: directories),
         :ok <- SecretsWatcherFileSystem.subscribe(watcher_pid) do
      {
        :ok,
        %State{
          callbacks: callbacks,
          secrets: load_secrets(secrets, trim_secrets),
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

      {:changed, secret_filename, wrapped_new_secret} ->
        Telemetry.event(:changed_secret, %{secret_filename: secret_filename})

        {
          :noreply,
          %{state | secrets: Map.put(state.secrets, secret_filename, wrapped_new_secret)},
          {:continue, {:notify_secret_rotation, secret_filename}}
        }
    end
  end

  @impl true
  def handle_info(_, state) do
    {:noreply, state}
  end

  @impl true
  def handle_continue({:notify_secret_rotation, secret_filename}, state) do
    wrapped_secret = Map.fetch!(state.secrets, secret_filename)
    callback = Map.fetch!(state.callbacks, secret_filename)

    {:ok, _task_pid} =
      Task.Supervisor.start_child(state.task_supervisor_pid, fn ->
        callback.(wrapped_secret)
      end)

    {:noreply, state}
  end

  @impl true
  def handle_call({:get_wrapped_secret, secret_name}, _from, %State{} = state) do
    response =
      case Map.get(state.secrets, secret_name) do
        nil -> {:error, :no_such_secret}
        wrapped_secret -> {:ok, wrapped_secret}
      end

    {:reply, response, state}
  end

  @impl true
  def handle_call({:delete_wrapped_secret, secret_name}, _from, %State{} = state) do
    secrets = Map.delete(state.secrets, secret_name)

    {:reply, :ok, %State{state | secrets: secrets}}
  end

  @impl true
  def handle_call({:put_wrapped_secret, secret_name, wrapped_secret}, _from, %State{} = state) do
    secrets = Map.put(state.secrets, secret_name, wrapped_secret)

    {:reply, :ok, %State{state | secrets: secrets}}
  end

  # -- Private

  defp load_secrets(secrets, trim_secrets) do
    secrets
    |> Enum.map(fn
      {secret_filename, secret_config} ->
        directory = Keyword.fetch!(secret_config, :directory)

        Telemetry.event(:initial_loading, %{
          secret_filename: secret_filename,
          directory: directory
        })

        {secret_filename, load_secret(directory, secret_filename, trim_secrets)}
    end)
    |> Enum.into(%{})
  end

  defp load_updated_secret(secrets, events, path, trim_secret) do
    import SecretsWatcher.Compare

    if contains_watched_events?(events) and is_file?(path) do
      {secret_filename, wrapped_new_secret} = load_secret_from_path(path, trim_secret)
      wrapped_previous_secret = Map.get(secrets, secret_filename)

      cond do
        # `secret_filename` is not in `secrets`, we can ignore it.
        wrapped_previous_secret == nil ->
          :ignore

        equal?(wrapped_previous_secret.(), wrapped_new_secret.()) ->
          :ignore

        true ->
          {:changed, secret_filename, wrapped_new_secret}
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

  defp load_secret(dir, secret_filename, trim_secret) do
    abs_path = Path.join(dir, secret_filename)
    {^secret_filename, wrapped_secret} = load_secret_from_path(abs_path, trim_secret)

    wrapped_secret
  end

  defp load_secret_from_path(path, trim_secret) do
    secret_filename = Path.basename(path)

    case File.read(path) do
      {:ok, secret} ->
        secret =
          if trim_secret do
            String.trim(secret)
          else
            secret
          end

        {secret_filename, fn -> secret end}

      {:error, _} ->
        {secret_filename, fn -> nil end}
    end
  end

  defp get_directories(secrets) when is_map(secrets) do
    Enum.reduce_while(secrets, {:ok, []}, fn {_secret_name, secret_config}, {:ok, acc} ->
      case Keyword.get(secret_config, :directory) do
        nil ->
          {:halt, {:error, :missing_directory}}

        directory ->
          if directory in acc do
            {:cont, {:ok, acc}}
          else
            {:cont, {:ok, [directory | acc]}}
          end
      end
    end)
  end

  defp make_callbacks(secrets) when is_map(secrets) do
    secrets
    |> Enum.map(fn {secret_filename, secret_config} ->
      case Keyword.get(secret_config, :callback) do
        nil -> {secret_filename, fn _ -> nil end}
        fun when is_function(fun) -> {secret_filename, fun}
      end
    end)
    |> Enum.into(%{})
  end
end
