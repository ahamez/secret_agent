defmodule SecretAgent.Telemetry do
  @moduledoc """
  `secret_agent` emits several [`telemetry`](https://github.com/beam-telemetry/telemetry) events.

  ## Events

  * `[:secret_agent, :file_event]`
    * _metadata_
      * `:events` the filesystem events
      * `:path` path to the file with events

  * `[:secret_agent, :changed_secret]`
    * _metadata_
      * `:secret_filename` filename of the secret that has changed

  * `[:secret_agent, :initial_loading]`
    * _metadata_
      * `:directory` directory in which initial loading took place
      * `:secret_filename` filename of the secret that has been loaded

  * `[:secret_agent, :unwatched_events]`
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
          [:secret_agent, :file_event],
          [:secret_agent, :changed_secret],
          [:secret_agent, :initial_loading],
          [:secret_agent, :unwatched_events]
        ],
        &SecretAgent.TelemetryLogger.handle_event/4,
        nil
      )
  end

  @doc false
  def event(event_name, metadata) do
    :telemetry.execute(
      [:secret_agent, event_name],
      _measurements = %{},
      metadata
    )
  end
end
