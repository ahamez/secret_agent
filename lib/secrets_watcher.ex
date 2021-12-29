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
    directory: [
      type: :string,
      required: true
    ],
    secrets: [
      type: :any,
      required: true
    ]
  ]

  use GenServer

  alias SecretsWatcher.Telemetry

  defmodule State do
    @moduledoc false
    defstruct callbacks: %{},
              directory: nil,
              directory_watcher_pid: nil,
              secrets: %{},
              task_supervisor_pid: nil
  end

  def child_spec(opts) do
    %{
      id: opts[:name] || __MODULE__,
      start: {__MODULE__, :start_link, [opts]}
    }
  end

  def start_link(opts) do
    {secrets_opts, opts} = Keyword.pop!(opts, :secrets_watcher_config)

    with {:ok, secrets_opts} <- NimbleOptions.validate(secrets_opts, @options_definition) do
      server_opts = Keyword.take(opts, [:name])
      GenServer.start_link(__MODULE__, secrets_opts, server_opts)
    end
  end

  @doc """
  Return the secret (wrapped in a closure) corresponding to `secret_filename`.
  """
  @spec get_wrapped_secret(pid() | atom(), binary()) :: {:ok, function()} | {:error, term()}
  def get_wrapped_secret(server, secret_filename) when is_binary(secret_filename) do
    GenServer.call(server, {:get_wrapped_secret, secret_filename})
  end

  # -- GenServer

  @impl true
  def init(opts) do
    {directory, opts} = Keyword.pop!(opts, :directory)
    {secrets, _opts} = Keyword.pop!(opts, :secrets)

    callbacks = make_callbacks(secrets)

    {:ok, task_supervisor_pid} = Task.Supervisor.start_link()

    {:ok, directory_watcher_pid} = SecretsWatcherFileSystem.start_link(dirs: [directory])
    SecretsWatcherFileSystem.subscribe(directory_watcher_pid)

    {
      :ok,
      %State{
        callbacks: callbacks,
        directory: directory,
        secrets: load_secrets(directory, callbacks),
        task_supervisor_pid: task_supervisor_pid,
        directory_watcher_pid: directory_watcher_pid
      }
    }
  end

  @impl true
  def handle_info({:file_event, _pid, {path, events}}, state) do
    Telemetry.event(:file_event, %{events: events, path: path})

    case load_updated_secret(state.secrets, events, path) do
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
  def handle_call({:get_wrapped_secret, secret_filename}, _from, %State{} = state) do
    response =
      case Map.get(state.secrets, secret_filename) do
        nil -> {:error, :no_such_secret}
        wrapped_secret -> {:ok, wrapped_secret}
      end

    {:reply, response, state}
  end

  # -- Private

  defp load_secrets(directory, callbacks) do
    callbacks
    |> Enum.map(fn {secret_filename, _callback} ->
      Telemetry.event(:initial_loading, %{secret_filename: secret_filename, directory: directory})

      {secret_filename, load_secret(directory, secret_filename)}
    end)
    |> Enum.into(%{})
  end

  defp load_updated_secret(secrets, events, path) do
    import SecretsWatcher.Compare

    if contains_watched_events?(events) and is_file?(path) do
      {secret_filename, wrapped_new_secret} = load_secret_from_path(path)
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

  defp load_secret(dir, secret_filename) do
    abs_path = Path.join(dir, secret_filename)
    {^secret_filename, wrapped_secret} = load_secret_from_path(abs_path)

    wrapped_secret
  end

  defp load_secret_from_path(path) do
    secret_filename = Path.basename(path)

    case File.read(path) do
      {:ok, secret} -> {secret_filename, fn -> secret end}
      {:error, _} -> {secret_filename, fn -> nil end}
    end
  end

  defp make_callbacks(secrets) when is_list(secrets) do
    secrets
    |> Enum.map(fn
      {secret_filename, callback} when is_binary(secret_filename) and is_function(callback) ->
        {secret_filename, callback}

      secret_filename when is_binary(secret_filename) ->
        {secret_filename, fn _ -> nil end}
    end)
    |> Enum.into(%{})
  end
end
