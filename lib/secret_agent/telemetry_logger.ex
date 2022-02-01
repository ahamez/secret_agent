defmodule SecretAgent.TelemetryLogger do
  @moduledoc false

  require Logger

  def handle_event([:secret_agent, event], _measurement, metadata, _config) do
    Logger.info("(secret_agent) #{event}: #{inspect(metadata)}")
  end
end
