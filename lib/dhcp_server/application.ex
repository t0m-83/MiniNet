defmodule DhcpServer.Application do
  @moduledoc """
  DHCP Server Application — OTP supervisor tree.
  """
  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    config = load_config()
    print_banner(config)

    children = [
      {DhcpServer.LeaseManager, config},
      {DhcpServer.Handler, []},
      {DhcpServer.Socket, [port: 67, bind_ip: {0, 0, 0, 0}, interface: "virbr2"]},
      {DhcpServer.Dns, [
        port: 53,
        bind_ip: {192, 168, 1, 1},     # Tuple explicite, pas de conversion binaire
        domain: config.domain,
        interface: "virbr2",
        upstream: {{8, 8, 8, 8}, 53}
      ]},
      {DhcpServer.StatusReporter, []}
    ]

    opts = [strategy: :one_for_one, name: DhcpServer.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp load_config do
    %{
      # Server identity
      server_ip:   ip("192.168.1.1"),

      # IP pool to distribute
      pool_start:  ip("192.168.1.100"),
      pool_end:    ip("192.168.1.200"),

      # Network configuration sent to clients
      subnet_mask: ip("255.255.255.0"),
      router:      ip("192.168.1.1"),
      # DNS servers — le serveur lui-même en premier, puis fallback Google
      dns_servers: [ip("192.168.1.1"), ip("8.8.8.8")],
      domain:      "home.local",

      # Lease duration in seconds (default: 24h)
      lease_time:  86_400,

      # Static reservations: MAC → IP
      # These clients will always get the same IP
      reservations: %{
        "aa:bb:cc:dd:ee:ff" => ip("192.168.1.50"),
        "11:22:33:44:55:66" => ip("192.168.1.51")
      }
    }
  end

  defp ip(str) do
    str
    |> String.split(".")
    |> Enum.map(&String.to_integer/1)
    |> :erlang.list_to_binary()
  end

  defp print_banner(config) do
    pool_size =
      (ip_to_int(config.pool_end) - ip_to_int(config.pool_start) + 1)

    Logger.info("""

    ╔══════════════════════════════════════════════════════════════════╗
    ║              DHCP SERVER — Elixir Implementation                 ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║  RFC 2131 compliant DHCP server                                  ║
    ║  Supports: DISCOVER, OFFER, REQUEST, ACK, NAK,                   ║
    ║            RELEASE, DECLINE, INFORM                              ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║  Server IP   : #{String.pad_trailing(ip_str(config.server_ip), 49)}║
    ║  Pool        : #{String.pad_trailing("#{ip_str(config.pool_start)} → #{ip_str(config.pool_end)} (#{pool_size} addrs)", 49)}║
    ║  Subnet mask : #{String.pad_trailing(ip_str(config.subnet_mask), 49)}║
    ║  Default GW  : #{String.pad_trailing(ip_str(config.router), 49)}║
    ║  DNS servers : #{String.pad_trailing(Enum.map_join(config.dns_servers, ", ", &ip_str/1), 49)}║
    ║  DNS domain  : #{String.pad_trailing(config.domain, 49)}║
    ║  DNS port    : 53 (local resolution + forward → 8.8.8.8)         ║
    ║  Lease time  : #{String.pad_trailing("#{div(config.lease_time, 3600)}h (#{config.lease_time}s)", 49)}║
    ║  Reservations: #{String.pad_trailing("#{map_size(config.reservations)} static entries", 49)}║
    ║  Listening   : UDP 0.0.0.0:67                                    ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
  end

  defp ip_str(<<a, b, c, d>>), do: "#{a}.#{b}.#{c}.#{d}"
  defp ip_to_int(<<a, b, c, d>>), do: a * 16_777_216 + b * 65_536 + c * 256 + d
end
