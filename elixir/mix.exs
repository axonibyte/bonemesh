defmodule Bonemesh.MixProject do
  use Mix.Project

  # The BoneMesh v3 Elixir implementation. OTP 28's :crypto provides ML-DSA,
  # ML-KEM, X25519, and ChaCha20-Poly1305 natively, and Elixir's built-in JSON
  # module handles the wire format, so this project needs no dependencies.
  def project do
    [
      app: :bonemesh,
      version: "3.0.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: []
    ]
  end

  def application do
    [extra_applications: [:crypto, :logger]]
  end
end
