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
    callbacks: [
      type: :any,
      required: true
    ]
  ]

  use GenServer

  require Logger

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
    {secrets_opts, opts} = Keyword.pop!(opts, :secrets)

    with {:ok, secrets_opts} <- NimbleOptions.validate(secrets_opts, @options_definition) do
      server_opts = Keyword.take(opts, [:name])
      GenServer.start_link(__MODULE__, secrets_opts, server_opts)
    end
  end

  @doc """
  Return the secret (wrapped in a closure) corresponding to `secret_name`.
  """
  @spec get_wrapped_secret(pid() | atom(), binary()) :: {:ok, function()} | {:error, term()}
  def get_wrapped_secret(server, secret_name) when is_binary(secret_name) do
    GenServer.call(server, {:get_wrapped_secret, secret_name})
  end

  # -- GenServer

  @impl true
  def init(opts) do
    {directory, opts} = Keyword.pop!(opts, :directory)
    {callbacks, _opts} = Keyword.pop!(opts, :callbacks)

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
    Logger.debug("Path #{inspect(path)}: #{inspect(events)}")

    case load_updated_secret(state.secrets, events, path) do
      :unchanged ->
        {:noreply, state}

      {:changed, secret_name, wrapped_new_secret} ->
        new_secrets = Map.put(state.secrets, secret_name, wrapped_new_secret)
        Logger.debug("Secret has changed", secret: secret_name)

        {:noreply, %{state | secrets: new_secrets},
         {:continue, {:notify_secret_rotation, secret_name}}}
    end
  end

  @impl true
  def handle_info(_, state) do
    Logger.warn("#{__MODULE__} received unhandled message")

    {:noreply, state}
  end

  @impl true
  def handle_continue({:notify_secret_rotation, secret_name}, state) do
    wrapped_secret = Map.fetch!(state.secrets, secret_name)
    callback = Map.fetch!(state.callbacks, secret_name)

    task =
      Task.Supervisor.start_child(state.task_supervisor_pid, fn ->
        callback.(wrapped_secret)
      end)

    case task do
      :ignore -> Logger.warn("Could not launch callback", secret: secret_name)
      {:error, _} -> Logger.warn("Could not launch callback", secret: secret_name)
      _ -> Logger.debug("Execute callback", secret: secret_name)
    end

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

  # -- Private

  defp load_secrets(directory, callbacks) do
    callbacks
    |> Enum.map(fn {secret_name, _callback} ->
      Logger.debug("Initial loading from '#{directory}'", secret: secret_name)

      {secret_name, load_secret(directory, secret_name)}
    end)
    |> Enum.into(%{})
  end

  defp load_updated_secret(secrets, events, path) do
    import SecretsWatcher.Compare

    if contains_watched_events?(events) and is_file?(path) do
      {secret_name, wrapped_new_secret} = load_secret_from_path(path)
      wrapped_previous_secret = Map.get(secrets, secret_name)

      cond do
        wrapped_previous_secret == nil ->
          :unchanged

        equal?(wrapped_previous_secret.(), wrapped_new_secret.()) ->
          :unchanged

        true ->
          {:changed, secret_name, wrapped_new_secret}
      end
    else
      Logger.debug("Unwatched events #{inspect(events)} on file #{path}")
      :unchanged
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

  defp load_secret(dir, secret_name) do
    abs_path = Path.join(dir, secret_name)
    {^secret_name, wrapped_secret} = load_secret_from_path(abs_path)

    wrapped_secret
  end

  defp load_secret_from_path(path) do
    secret_name = Path.basename(path)

    case File.read(path) do
      {:ok, secret} -> {secret_name, fn -> secret end}
      {:error, _} -> {secret_name, fn -> nil end}
    end
  end
end
