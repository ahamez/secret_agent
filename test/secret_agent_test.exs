defmodule SecretAgentTest do
  use ExUnit.Case
  doctest SecretAgent

  describe "Launch process" do
    test "Success: start_link/1" do
      assert {:ok, _pid} = start_supervised({SecretAgent, secret_agent_config: [secrets: %{}]})
    end

    test "Success: start_link/1 with name" do
      assert {:ok, pid} =
               start_supervised({SecretAgent, secret_agent_config: [secrets: %{}], name: :foo})

      assert ^pid = Process.whereis(:foo)
    end

    test "Failure: missing option" do
      assert {:error, {%NimbleOptions.ValidationError{}, _}} =
               start_supervised({SecretAgent, secret_agent_config: []})
    end

    test "Failure: invalid key in secret config" do
      assert {:error, {{:invalid_secret_config, "secret_name", [:invalid_option]}, _}} =
               start_supervised(
                 {SecretAgent,
                  secret_agent_config: [
                    secrets: %{"secret_name" => [invalid_option: :dummy]}
                  ]}
               )
    end
  end

  describe "Secrets management" do
    test "Success: secret with no initial file is nil" do
      pid =
        start_supervised!(
          {SecretAgent,
           secret_agent_config: [
             secrets: %{"secret" => [directory: "", callback: fn _ -> :dummy end]}
           ]}
        )

      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, "secret")
      assert wrapped_secret.() == nil
    end

    test "Success: read secret from initial file, secret having a callback" do
      tmp_dir = mk_tmp_random_dir()
      {_path, secret} = mk_random_secret(tmp_dir)

      pid =
        start_supervised!(
          {SecretAgent,
           secret_agent_config: [
             secrets: %{secret => [callback: fn _ -> :dummy end, directory: tmp_dir]}
           ]}
        )

      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, secret)
      assert wrapped_secret.() == secret
    end

    test "Success: read secret from initial file, secret having no callback" do
      tmp_dir = mk_tmp_random_dir()
      {_path, secret} = mk_random_secret(tmp_dir)

      pid =
        start_supervised!(
          {SecretAgent, secret_agent_config: [secrets: %{secret => [directory: tmp_dir]}]}
        )

      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, secret)
      assert wrapped_secret.() == secret
    end

    test "Success: read secrets from multiple directories" do
      tmp_dir_1 = mk_tmp_random_dir()
      tmp_dir_2 = mk_tmp_random_dir()

      {_path, secret_1} = mk_random_secret(tmp_dir_1)
      {_path, secret_2} = mk_random_secret(tmp_dir_2)

      pid =
        start_supervised!(
          {SecretAgent,
           secret_agent_config: [
             secrets: %{secret_1 => [directory: tmp_dir_1], secret_2 => [directory: tmp_dir_2]}
           ]}
        )

      assert {:ok, wrapped_secret_1} = SecretAgent.get_secret(pid, secret_1)
      assert wrapped_secret_1.() == secret_1

      assert {:ok, wrapped_secret_2} = SecretAgent.get_secret(pid, secret_2)
      assert wrapped_secret_2.() == secret_2
    end

    test "Failure: accessing a non-existing secret returns an error" do
      pid = start_supervised!({SecretAgent, secret_agent_config: [secrets: %{}]})

      assert {:error, :no_such_secret} = SecretAgent.get_secret(pid, "non_existing_secret")
    end

    test "Success: read in-memory secret from initial value " do
      pid =
        start_supervised!(
          {SecretAgent,
           secret_agent_config: [secrets: %{"in-memory-secret" => [value: "initial"]}]}
        )

      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, "in-memory-secret")

      assert wrapped_secret.() == "initial"
    end

    test "Success: read in-memory secret without initial value is nil" do
      pid =
        start_supervised!(
          {SecretAgent, secret_agent_config: [secrets: %{"in-memory-secret" => []}]}
        )

      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, "in-memory-secret")

      assert wrapped_secret.() == nil
    end

    test "Success: initial value supersed file value" do
      tmp_dir = mk_tmp_random_dir()
      {_path, secret} = mk_random_secret(tmp_dir)

      pid =
        start_supervised!(
          {SecretAgent,
           secret_agent_config: [secrets: %{secret => [directory: tmp_dir, value: "initial"]}]}
        )

      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, secret)

      assert wrapped_secret.() == "initial"
    end

    test "Success: launch init_callback when reading file for the first time" do
      tmp_dir = mk_tmp_random_dir()

      {_secret_path, secret} = mk_random_secret(tmp_dir)

      test_pid = self()
      test_ref = make_ref()

      start_supervised!(
        {SecretAgent,
         secret_agent_config: [
           secrets: %{
             secret => [
               directory: tmp_dir,
               init_callback: fn wrapped_secret ->
                 send(test_pid, {test_ref, secret, wrapped_secret.()})
               end
             ]
           }
         ]}
      )

      assert_receive {^test_ref, ^secret, ^secret}
    end

    test "Success: a secret is erased after having being accessed" do
      pid =
        start_supervised!(
          {SecretAgent, secret_agent_config: [secrets: %{"secret" => [value: "some_value"]}]}
        )

      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, "secret")
      assert wrapped_secret.() == "some_value"

      assert {:ok, :erased} = SecretAgent.get_secret(pid, "secret")
    end

    test "Success: can override erasing a secret" do
      pid =
        start_supervised!(
          {SecretAgent, secret_agent_config: [secrets: %{"secret" => [value: "some_value"]}]}
        )

      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, "secret", erase: false)
      assert wrapped_secret.() == "some_value"

      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, "secret")
      assert wrapped_secret.() == "some_value"
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
          {SecretAgent,
           secret_agent_config: [secrets: %{"secret_with_whitespaces" => [directory: tmp_dir]}]}
        )

      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, "secret_with_whitespaces")

      assert wrapped_secret.() == String.trim(secret_with_whitespaces)
    end

    test "Success: trim deactivated" do
      tmp_dir = mk_tmp_random_dir()
      secret_with_whitespaces = "   \nsecret\n  \n"
      path = Path.join(tmp_dir, "secret_with_whitespaces")
      File.write!(path, secret_with_whitespaces)

      pid =
        start_supervised!(
          {SecretAgent,
           secret_agent_config: [
             secrets: %{"secret_with_whitespaces" => [directory: tmp_dir]},
             trim_secrets: false
           ]}
        )

      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, "secret_with_whitespaces")

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
          {SecretAgent,
           secret_agent_config: [
             secrets: %{
               secret => [
                 directory: tmp_dir,
                 callback: fn wrapped_secret ->
                   send(test_pid, {test_ref, secret, wrapped_secret.()})
                 end
               ]
             }
           ]}
        )

      %SecretAgent.State{watcher_pid: watcher_pid} = :sys.get_state(pid)

      # Callback should be called when the content has been modified
      File.write!(secret_path, "new_secret_content")
      send(pid, {:file_event, watcher_pid, {secret_path, [:modified]}})
      assert_receive {^test_ref, ^secret, "new_secret_content"}

      # Callback should not be called when the content hasn't been modified
      File.write!(secret_path, "new_secret_content")
      send(pid, {:file_event, watcher_pid, {secret_path, [:modified]}})
      refute_receive {^test_ref, ^secret, "new_secret_content"}
    end

    test "Success: callbacks are invoked upon secret rotation in multiple directories" do
      tmp_dir_1 = mk_tmp_random_dir()
      tmp_dir_2 = mk_tmp_random_dir()

      {secret_path_1, secret_1} = mk_random_secret(tmp_dir_1)
      {secret_path_2, secret_2} = mk_random_secret(tmp_dir_2)

      test_pid = self()
      test_ref = make_ref()

      pid =
        start_supervised!(
          {SecretAgent,
           secret_agent_config: [
             secrets: %{
               secret_1 => [
                 directory: tmp_dir_1,
                 callback: fn wrapped_secret_1 ->
                   send(test_pid, {test_ref, secret_1, wrapped_secret_1.()})
                 end
               ],
               secret_2 => [
                 directory: tmp_dir_2,
                 callback: fn wrapped_secret_2 ->
                   send(test_pid, {test_ref, secret_2, wrapped_secret_2.()})
                 end
               ]
             }
           ]}
        )

      %SecretAgent.State{watcher_pid: watcher_pid} = :sys.get_state(pid)

      # Callback should be called when the content has been modified
      File.write!(secret_path_1, "new_secret_content_1")
      send(pid, {:file_event, watcher_pid, {secret_path_1, [:modified]}})
      assert_receive {^test_ref, ^secret_1, "new_secret_content_1"}

      # Callback should be called when the content has been modified
      File.write!(secret_path_2, "new_secret_content_2")
      send(pid, {:file_event, watcher_pid, {secret_path_2, [:modified]}})
      assert_receive {^test_ref, ^secret_2, "new_secret_content_2"}
    end

    test "Success: updating a file that is not a watched secret doesn't update a watched secret" do
      tmp_dir = mk_tmp_random_dir()
      unwatched_secret_path = Path.join(tmp_dir, "unwatched_secret")

      pid =
        start_supervised!(
          {SecretAgent, secret_agent_config: [secrets: %{"some_secret" => [directory: tmp_dir]}]}
        )

      %SecretAgent.State{watcher_pid: watcher_pid} = :sys.get_state(pid)

      File.write!(unwatched_secret_path, "dummy")
      send(pid, {:file_event, watcher_pid, {unwatched_secret_path, [:modified]}})

      {:ok, some_wrapped_secret} = assert SecretAgent.get_secret(pid, "some_secret")
      assert some_wrapped_secret.() == nil
    end

    test "Success: watched secret with initial value can be updated from disk" do
      tmp_dir = mk_tmp_random_dir()
      {secret_path, secret} = mk_random_secret(tmp_dir)

      pid =
        start_supervised!(
          {SecretAgent,
           secret_agent_config: [secrets: %{secret => [directory: tmp_dir, value: "initial"]}]}
        )

      %SecretAgent.State{watcher_pid: watcher_pid} = :sys.get_state(pid)

      File.write!(secret_path, "new_secret_content")
      send(pid, {:file_event, watcher_pid, {secret_path, [:modified]}})

      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, secret)
      assert wrapped_secret.() == "new_secret_content"
    end
  end

  describe "Set and erase secrets manually" do
    test "Success: can put a secret" do
      pid = start_supervised!({SecretAgent, secret_agent_config: [secrets: %{}]})

      assert :ok = SecretAgent.put_secret(pid, "foo", fn -> "supersecret" end)

      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, "foo")
      assert wrapped_secret.() == "supersecret"
    end

    test "Success: can erase a manually added secret" do
      pid = start_supervised!({SecretAgent, secret_agent_config: [secrets: %{}]})

      assert :ok = SecretAgent.put_secret(pid, "foo", fn -> "supersecret" end)

      assert :ok = SecretAgent.erase_secret(pid, "foo")
      assert {:ok, :erased} = SecretAgent.get_secret(pid, "foo")
    end

    test "Success: can erase a watched secret" do
      tmp_dir = mk_tmp_random_dir()

      {secret_path, secret} = mk_random_secret(tmp_dir)

      pid =
        start_supervised!(
          {SecretAgent, secret_agent_config: [secrets: %{secret => [directory: tmp_dir]}]}
        )

      %SecretAgent.State{watcher_pid: watcher_pid} = :sys.get_state(pid)

      assert :ok = SecretAgent.erase_secret(pid, secret)
      assert {:ok, :erased} = SecretAgent.get_secret(pid, secret)

      # A watched secret can be updated if its content changes on disk.
      File.write!(secret_path, "new_secret_content")
      send(pid, {:file_event, watcher_pid, {secret_path, [:modified]}})
      assert {:ok, wrapped_secret} = SecretAgent.get_secret(pid, secret)
      assert wrapped_secret.() == "new_secret_content"
    end

    test "Success: nothing happens when deleting a non-existing secret" do
      pid = start_supervised!({SecretAgent, secret_agent_config: [secrets: %{}]})

      assert :ok = SecretAgent.erase_secret(pid, "non_existing_secret")
    end
  end

  describe "Telemetry" do
    test "Success: :file_event" do
      defmodule Handler do
        def handler(event, _measurements, _metadata, config) do
          assert event == [:secret_agent, :file_event]
          send(config.parent, {config.ref, :file_event_emitted})
        end
      end

      {test_name, _arity} = __ENV__.function
      parent = self()
      ref = make_ref()

      :telemetry.attach(
        to_string(test_name),
        [:secret_agent, :file_event],
        &Handler.handler/4,
        %{parent: parent, ref: ref}
      )

      pid =
        start_supervised!(
          {SecretAgent,
           secret_agent_config: [secrets: %{"dummy_secret" => [directory: "dummy_dir"]}]}
        )

      %SecretAgent.State{watcher_pid: watcher_pid} = :sys.get_state(pid)

      send(pid, {:file_event, watcher_pid, {"/dummy/path", [:modified]}})

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