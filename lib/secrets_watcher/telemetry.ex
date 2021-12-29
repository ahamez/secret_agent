defmodule SecretsWatcher.Telemetry do
  @moduledoc """
  `secrets_watcher` emits several [`telemetry`](https://github.com/beam-telemetry/telemetry) events.

  ## Events

  * `[:secrets_watcher, :file_event]`
    * _metadata_
      * `:events` the filesystem events
      * `:path` path to the file with events

  * `[:secrets_watcher, :changed_secret]`
    * _metadata_
      * `:secret_filename` filename of the secret that has changed

  * `[:secrets_watcher, :initial_loading]`
    * _metadata_
      * `:directory` directory in which initial loading took place
      * `:secret_filename` filename of the secret that has been loaded

  * `[:secrets_watcher, :unwatched_events]`
    * _metadata_
      * `:events` the filesystem events that have been ignored
      * `:path` path to the file with events
  """

  @doc """
  Call this function to have events logged automatically.
  """
  def attach_logger() do
    :ok =
      :telemetry.attach_many(
        "log-secrets-watcher-events",
        [
          [:secrets_watcher, :file_event],
          [:secrets_watcher, :changed_secret],
          [:secrets_watcher, :initial_loading],
          [:secrets_watcher, :unwatched_events]
        ],
        &SecretsWatcher.TelemetryLogger.handle_event/4,
        nil
      )
  end

  @doc false
  def event(event_name, metadata) do
    :telemetry.execute(
      [:secrets_watcher, event_name],
      _measurements = %{},
      metadata
    )
  end
end
