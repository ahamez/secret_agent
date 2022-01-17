defmodule SecretsWatcherTest do
  use ExUnit.Case
  doctest SecretsWatcher

  SecretsWatcher.Telemetry.attach_logger()

  describe "Launch process" do
    test "Success: start_link/1" do
      assert {:ok, _pid} =
               start_supervised(
                 {SecretsWatcher, secrets_watcher_config: [directory: "", secrets: []]}
               )
    end

    test "Success: start_link/1 with name" do
      assert {:ok, pid} =
               start_supervised(
                 {SecretsWatcher,
                  secrets_watcher_config: [directory: "", secrets: []], name: :foo}
               )

      assert ^pid = Process.whereis(:foo)
    end

    test "Failure: missing option" do
      assert {:error, {%NimbleOptions.ValidationError{}, _}} =
               start_supervised({SecretsWatcher, secrets_watcher_config: [directory: ""]})
    end
  end

  describe "Secrets management" do
    test "Success: secret with no initial file is nil" do
      pid =
        start_supervised!(
          {SecretsWatcher,
           secrets_watcher_config: [
             directory: "",
             secrets: [{"secret", fn _ -> :dummy end}]
           ]}
        )

      assert {:ok, wrapped_secret} = SecretsWatcher.get_wrapped_secret(pid, "secret")
      assert wrapped_secret.() == nil
    end

    test "Success: read secret from initial file, secret having a callback" do
      tmp_dir = mk_tmp_random_dir()
      {_path, secret} = mk_random_secret(tmp_dir)

      pid =
        start_supervised!(
          {SecretsWatcher,
           secrets_watcher_config: [
             directory: tmp_dir,
             secrets: [{secret, fn _ -> :dummy end}]
           ]}
        )

      assert {:ok, wrapped_secret} = SecretsWatcher.get_wrapped_secret(pid, secret)
      assert wrapped_secret.() == secret
    end

    test "Success: read secret from initial file, secret having no callback" do
      tmp_dir = mk_tmp_random_dir()
      {_path, secret} = mk_random_secret(tmp_dir)

      pid =
        start_supervised!(
          {SecretsWatcher, secrets_watcher_config: [directory: tmp_dir, secrets: [secret]]}
        )

      assert {:ok, wrapped_secret} = SecretsWatcher.get_wrapped_secret(pid, secret)
      assert wrapped_secret.() == secret
    end

    test "Failure: accessing a non-existing secret returns an error" do
      pid =
        start_supervised!({SecretsWatcher, secrets_watcher_config: [directory: "", secrets: []]})

      assert {:error, :no_such_secret} =
               SecretsWatcher.get_wrapped_secret(pid, "non_existing_secret")
    end
  end

  describe "Trim" do
    test "Success: trim activated by default" do
      tmp_dir = mk_tmp_random_dir()
      secret_with_whitespaces = "   \nsecret\n  \n"
      path = Path.join(tmp_dir, "secret_with_whitespaces")
      File.write!(path, secret_with_whitespaces)

      pid =
        start_supervised!(
          {SecretsWatcher,
           secrets_watcher_config: [directory: tmp_dir, secrets: ["secret_with_whitespaces"]]}
        )

      assert {:ok, wrapped_secret} =
               SecretsWatcher.get_wrapped_secret(pid, "secret_with_whitespaces")

      assert wrapped_secret.() == String.trim(secret_with_whitespaces)
    end

    test "Success: trim deactivated" do
      tmp_dir = mk_tmp_random_dir()
      secret_with_whitespaces = "   \nsecret\n  \n"
      path = Path.join(tmp_dir, "secret_with_whitespaces")
      File.write!(path, secret_with_whitespaces)

      pid =
        start_supervised!(
          {SecretsWatcher,
           secrets_watcher_config: [
             directory: tmp_dir,
             secrets: ["secret_with_whitespaces"],
             trim_secrets: false
           ]}
        )

      assert {:ok, wrapped_secret} =
               SecretsWatcher.get_wrapped_secret(pid, "secret_with_whitespaces")

      assert wrapped_secret.() == secret_with_whitespaces
    end
  end

  describe "Secrets rotation" do
    test "Success: callback is invoked upon secret rotation" do
      tmp_dir = mk_tmp_random_dir()

      {secret_path, secret} = mk_random_secret(tmp_dir)

      test_pid = self()
      test_ref = make_ref()

      pid =
        start_supervised!(
          {SecretsWatcher,
           secrets_watcher_config: [
             directory: tmp_dir,
             secrets: [
               {
                 secret,
                 fn wrapped_secret -> send(test_pid, {test_ref, secret, wrapped_secret.()}) end
               }
             ]
           ]}
        )

      # Callback should be called when the content has been modified
      File.write!(secret_path, "new_secret_content")
      send(pid, {:file_event, :dummy_pid, {secret_path, [:modified]}})
      assert_receive {^test_ref, ^secret, "new_secret_content"}

      # Callback should not be called when the content hasn't been modified
      File.write!(secret_path, "new_secret_content")
      send(pid, {:file_event, :dummy_pid, {secret_path, [:modified]}})
      refute_receive {^test_ref, ^secret, "new_secret_content"}
    end

    test "Success: update a file that is not a watched secret doesn't update a watched secret" do
      tmp_dir = mk_tmp_random_dir()
      unwatched_secret_path = Path.join(tmp_dir, "unwatched_secret")

      pid =
        start_supervised!(
          {SecretsWatcher, secrets_watcher_config: [directory: tmp_dir, secrets: ["some_secret"]]}
        )

      File.write!(unwatched_secret_path, "dummy")
      send(pid, {:file_event, :dummy_pid, {unwatched_secret_path, [:modified]}})

      {:ok, some_wrapped_secret} = assert SecretsWatcher.get_wrapped_secret(pid, "some_secret")
      assert some_wrapped_secret.() == nil
    end
  end

  describe "Telemetry" do
    test "Success: :file_event" do
      {test_name, _arity} = __ENV__.function
      parent = self()
      ref = make_ref()

      handler = fn event, _measurements, _metadata, _config ->
        assert event == [:secrets_watcher, :file_event]
        send(parent, {ref, :file_event_emitted})
      end

      :telemetry.attach(
        to_string(test_name),
        [:secrets_watcher, :file_event],
        handler,
        nil
      )

      pid =
        start_supervised!(
          {SecretsWatcher, secrets_watcher_config: [directory: "dummy_dir", secrets: []]}
        )

      send(pid, {:file_event, :dummy_pid, {"/dummy/path", [:modified]}})

      assert_receive {^ref, :file_event_emitted}
    end
  end

  # -- Helper functions

  defp mk_tmp_random_dir() do
    random_name = "#{Enum.take_random(?a..?z, 16)}"
    path = Path.join(System.tmp_dir!(), random_name)
    File.mkdir_p!(path)

    path
  end

  defp mk_random_secret(directory) do
    random_secret = "#{Enum.take_random(?a..?z, 16)}"
    path = Path.join(directory, random_secret)
    File.write!(path, random_secret)

    {path, random_secret}
  end
end
