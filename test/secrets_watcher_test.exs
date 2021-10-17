defmodule SecretsWatcherTest do
  use ExUnit.Case
  doctest SecretsWatcher

  describe "Launch process" do
    test "Success: start_link/1" do
      assert {:ok, _pid} =
               start_supervised({SecretsWatcher, secrets: [directory: "", callbacks: %{}]})
    end

    test "Success: start_link/1 with name" do
      assert {:ok, pid} =
               start_supervised(
                 {SecretsWatcher, secrets: [directory: "", callbacks: %{}], name: :foo}
               )

      assert ^pid = Process.whereis(:foo)
    end

    test "Failure: missing option" do
      assert {:error, {%NimbleOptions.ValidationError{}, _}} =
               start_supervised({SecretsWatcher, secrets: [directory: ""]})
    end
  end

  describe "Secrets management" do
    test "Success: secret with no initial file is nil" do
      pid =
        start_supervised!(
          {SecretsWatcher,
           secrets: [
             directory: "",
             callbacks: %{"secret" => fn _, _ -> nil end}
           ]}
        )

      assert {:ok, wrapped_secret} = SecretsWatcher.get_wrapped_secret(pid, "secret")
      assert wrapped_secret.() == nil
    end

    test "Success: read secret from initial file" do
      tmp_dir = mk_tmp_random_dir()
      {_path, secret_name} = mk_random_secret(tmp_dir)

      pid =
        start_supervised!(
          {SecretsWatcher,
           secrets: [
             directory: tmp_dir,
             callbacks: %{secret_name => fn _, _ -> nil end}
           ]}
        )

      assert {:ok, wrapped_secret} = SecretsWatcher.get_wrapped_secret(pid, secret_name)
      assert wrapped_secret.() == secret_name
    end

    test "Failure: accessing a non-existing secret returns an error" do
      pid = start_supervised!({SecretsWatcher, secrets: [directory: "", callbacks: %{}]})

      assert {:error, :no_such_secret} =
               SecretsWatcher.get_wrapped_secret(pid, "non_existing_secret")
    end
  end

  describe "Secrets rotation" do
    test "Success: callback is invoked upon secret rotation" do
      tmp_dir = mk_tmp_random_dir()
      {secret_path, secret_name} = mk_random_secret(tmp_dir)

      test_pid = self()
      test_ref = make_ref()

      pid =
        start_supervised!(
          {SecretsWatcher,
           secrets: [
             directory: tmp_dir,
             callbacks: %{
               secret_name => fn secret_name, wrapped_secret ->
                 send(test_pid, {test_ref, secret_name, wrapped_secret.()})
               end
             }
           ]}
        )

      %{directory_watcher_pid: watcher_pid} = :sys.get_state(pid)

      # Callback should be called when the content has been modified
      File.write!(secret_path, "new_secret_content")
      send(pid, {:file_event, watcher_pid, {secret_path, [:modified]}})
      assert_receive {^test_ref, ^secret_name, "new_secret_content"}

      # Callback should not be called when the content hasn't been modified
      File.write!(secret_path, "new_secret_content")
      send(pid, {:file_event, watcher_pid, {secret_path, [:modified]}})
      refute_receive {^test_ref, ^secret_name, "new_secret_content"}
    end

    test "Success: update a file that is not a secret" do
      tmp_dir = mk_tmp_random_dir()
      unwatched_secret_path = Path.join(tmp_dir, "unwatched_secret")

      pid =
        start_supervised!(
          {SecretsWatcher,
           secrets: [directory: tmp_dir, callbacks: %{"some_secret" => fn _, _ -> nil end}]}
        )

      %{directory_watcher_pid: watcher_pid} = :sys.get_state(pid)
      File.write!(unwatched_secret_path, "dummy")
      send(pid, {:file_event, watcher_pid, {unwatched_secret_path, [:modified]}})

      {:ok, some_wrapped_secret} = assert SecretsWatcher.get_wrapped_secret(pid, "some_secret")
      assert some_wrapped_secret.() == nil
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
