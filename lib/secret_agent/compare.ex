defmodule SecretAgent.Compare do
  @moduledoc """
  This module provides a function to compare secrets in constant time to
  avoid timing attacks.
  """

  import Bitwise

  @doc """
  Compares `lhs` and `rhs` binaries in constant time.

  ## Examples
      iex> equal?("abc", "abc")
      true

      iex> equal?("abc", "abcd")
      false
  """
  def equal?(lhs, rhs)
      when is_binary(lhs) and is_binary(rhs) and byte_size(lhs) != byte_size(rhs) do
    false
  end

  def equal?(lhs, rhs) when is_binary(lhs) and is_binary(rhs) do
    compare_secrets(0, lhs, rhs)
  end

  # -- Private

  defp compare_secrets(acc, <<l, lhs::binary>>, <<r, rhs::binary>>) do
    compare_secrets(acc ||| bxor(l, r), lhs, rhs)
  end

  defp compare_secrets(acc, <<>>, <<>>) do
    acc == 0
  end
end
