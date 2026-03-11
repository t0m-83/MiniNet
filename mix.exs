defmodule DhcpServer.MixProject do
  use Mix.Project

  def project do
    [
      app: :dhcp_server,
      version: "1.0.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "A DHCP server implementation in Elixir"
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {DhcpServer.Application, []}
    ]
  end

  defp deps do
    []
  end
end
