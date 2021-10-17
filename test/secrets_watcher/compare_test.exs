defmodule SecretsWatcher.CompareTest do
  use ExUnit.Case

  import SecretsWatcher.Compare
  doctest SecretsWatcher.Compare

  test "Success: empty binaries" do
    assert equal?("", "") == true
  end

  test "Failure: raise when not binaries" do
    assert_raise FunctionClauseError, fn ->
      equal?("abc", 0)
    end
  end
end
