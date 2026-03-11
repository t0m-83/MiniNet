defmodule DhcpServer do
  @moduledoc """
  DHCP Server — Top-level module.

  A fully functional DHCP server implementing RFC 2131.

  ## Features
  - DORA process: DISCOVER → OFFER → REQUEST → ACK
  - DHCPNAK for invalid requests
  - DHCPRELEASE — IP reclamation
  - DHCPDECLINE — conflict detection
  - DHCPINFORM — stateless config (for static-IP clients)
  - Lease expiration & automatic pool reclamation
  - Static IP reservations by MAC address
  - Real-time console logging
  - Periodic lease table status report

  ## Usage
      # Start server (requires root for port 67)
      sudo mix run --no-halt

      # Or in IEx
      sudo iex -S mix

      # View current leases
      DhcpServer.status()

      # Add a static reservation
      DhcpServer.reserve("aa:bb:cc:dd:ee:ff", "192.168.1.50")
  """

  alias DhcpServer.{LeaseManager, StatusReporter, Packet}

  @doc "Print current lease table to console"
  def status do
    StatusReporter.print_status()
  end

  @doc "List all leases as a list"
  def leases do
    LeaseManager.list_leases()
  end

  @doc "Add a static MAC→IP reservation"
  def reserve(mac, ip_str) do
    ip = ip_str |> String.split(".") |> Enum.map(&String.to_integer/1) |> :erlang.list_to_binary()
    LeaseManager.add_reservation(mac, ip)
  end

  @doc "Release a client's lease by MAC address"
  def release(mac) do
    case LeaseManager.get_lease_by_mac(mac) do
      nil ->
        IO.puts("No active lease for #{mac}")
      lease ->
        LeaseManager.release_lease(mac, lease.ip)
        IO.puts("Released #{Packet.ip_to_string(lease.ip)} from #{mac}")
    end
  end
end
