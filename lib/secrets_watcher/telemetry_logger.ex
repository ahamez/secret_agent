defmodule SecretsWatcher.TelemetryLogger do
  @moduledoc false

  require Logger

  def handle_event([:secrets_watcher, event], _measurement, metadata, _config) do
    Logger.info("(secrets_watcher) #{event}: #{inspect(metadata)}")
  end
end
