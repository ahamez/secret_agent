defmodule SecretAgent.CompareTest do
  use ExUnit.Case

  import SecretAgent.Compare
  doctest SecretAgent.Compare

  test "Success: empty binaries" do
    assert equal?("", "") == true
  end

  test "Failure: raise when not binaries" do
    assert_raise FunctionClauseError, fn ->
      equal?("abc", 0)
    end
  end
end
