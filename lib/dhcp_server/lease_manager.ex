defmodule DhcpServer.LeaseManager do
  @moduledoc """
  Manages the DHCP IP address pool and lease lifecycle.
  Handles assignment, renewal, expiration and release of leases.
  """
  use GenServer
  require Logger

  alias DhcpServer.Packet

  @check_interval 10_000  # Check expired leases every 10s

  defstruct [
    :pool_start,
    :pool_end,
    :lease_time,
    :subnet_mask,
    :router,
    :dns_servers,
    :server_ip,
    :domain,
    leases: %{},        # ip_binary => lease_info
    mac_to_ip: %{},     # mac_string => ip_binary
    reserved: %{}       # mac_string => ip_binary (static reservations)
  ]

  defmodule Lease do
    @moduledoc "Represents a single DHCP lease"
    defstruct [:ip, :mac, :hostname, :offered_at, :leased_at, :expires_at, :state, :xid]
    # state: :offered | :active | :expired | :released
  end

  # ---- Public API ----

  def start_link(config) do
    GenServer.start_link(__MODULE__, config, name: __MODULE__)
  end

  @doc "Get or create an IP offer for a given MAC address"
  def get_offer(mac, xid, hostname \\ nil) do
    GenServer.call(__MODULE__, {:get_offer, mac, xid, hostname})
  end

  @doc "Confirm a lease (DHCPREQUEST → DHCPACK)"
  def confirm_lease(mac, requested_ip, xid) do
    GenServer.call(__MODULE__, {:confirm_lease, mac, requested_ip, xid})
  end

  @doc "Release a lease"
  def release_lease(mac, ip) do
    GenServer.call(__MODULE__, {:release_lease, mac, ip})
  end

  @doc "Decline an offered IP"
  def decline_offer(mac, ip) do
    GenServer.call(__MODULE__, {:decline_offer, mac, ip})
  end

  @doc "Get current lease info for a MAC"
  def get_lease_by_mac(mac) do
    GenServer.call(__MODULE__, {:get_lease_by_mac, mac})
  end

  @doc "Get all active leases (for status display)"
  def list_leases do
    GenServer.call(__MODULE__, :list_leases)
  end

  @doc "Add a static reservation"
  def add_reservation(mac, ip) do
    GenServer.call(__MODULE__, {:add_reservation, mac, ip})
  end

  @doc "Get server configuration"
  def get_config do
    GenServer.call(__MODULE__, :get_config)
  end

  # ---- GenServer callbacks ----

  @impl true
  def init(config) do
    Logger.info("🗄️  LeaseManager initializing...")

    state = %__MODULE__{
      pool_start:   config.pool_start,
      pool_end:     config.pool_end,
      lease_time:   config.lease_time,
      subnet_mask:  config.subnet_mask,
      router:       config.router,
      dns_servers:  config.dns_servers,
      server_ip:    config.server_ip,
      domain:       Map.get(config, :domain, "local"),
      reserved:     Map.get(config, :reservations, %{})
    }

    pool_size = ip_to_int(state.pool_end) - ip_to_int(state.pool_start) + 1
    Logger.info("📦 IP pool: #{Packet.ip_to_string(state.pool_start)} - #{Packet.ip_to_string(state.pool_end)} (#{pool_size} addresses)")
    Logger.info("⏱️  Default lease time: #{state.lease_time}s (#{div(state.lease_time, 3600)}h)")

    if map_size(state.reserved) > 0 do
      Logger.info("📌 Static reservations: #{map_size(state.reserved)}")
      Enum.each(state.reserved, fn {mac, ip} ->
        Logger.info("   #{mac} → #{Packet.ip_to_string(ip)}")
      end)
    end

    # Schedule periodic lease expiry check
    :timer.send_interval(@check_interval, :check_expired_leases)

    {:ok, state}
  end

  @impl true
  def handle_call({:get_offer, mac, xid, hostname}, _from, state) do
    case find_or_assign_ip(mac, state) do
      {:ok, ip, state} ->
        now = System.system_time(:second)
        lease = %Lease{
          ip: ip,
          mac: mac,
          hostname: hostname,
          offered_at: now,
          expires_at: now + 30,  # 30s to confirm the offer
          state: :offered,
          xid: xid
        }
        state = put_lease(state, ip, mac, lease)
        Logger.info("📤 OFFER: #{Packet.ip_to_string(ip)} → #{mac}#{format_hostname(hostname)} [xid=#{format_xid(xid)}]")
        {:reply, {:ok, ip, lease_options(state)}, state}

      {:error, reason} ->
        Logger.warning("⚠️  No IP available for #{mac}: #{reason}")
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:confirm_lease, mac, requested_ip, xid}, _from, state) do
    with {:ok, current_ip} <- get_mac_ip(state, mac),
         true <- current_ip == requested_ip || check_requested_ip(state, requested_ip, mac) do

      ip = requested_ip
      now = System.system_time(:second)
      hostname = case Map.get(state.leases, ip) do
        nil -> nil
        lease -> lease.hostname
      end

      lease = %Lease{
        ip: ip,
        mac: mac,
        hostname: hostname,
        leased_at: now,
        expires_at: now + state.lease_time,
        state: :active,
        xid: xid
      }

      state = put_lease(state, ip, mac, lease)
      expires_in = format_duration(state.lease_time)
      Logger.info("✅ ACK: #{Packet.ip_to_string(ip)} → #{mac}#{format_hostname(hostname)} [lease=#{expires_in}]")

      {:reply, {:ok, ip, lease_options(state)}, state}
    else
      _ ->
        Logger.warning("❌ NAK: #{mac} requested #{Packet.ip_to_string(requested_ip)} (invalid/unavailable)")
        {:reply, {:error, :nak}, state}
    end
  end

  @impl true
  def handle_call({:release_lease, mac, ip}, _from, state) do
    case Map.get(state.leases, ip) do
      %Lease{mac: ^mac} = lease ->
        lease = %{lease | state: :released, expires_at: System.system_time(:second)}
        state = %{state |
          leases: Map.put(state.leases, ip, lease),
          mac_to_ip: Map.delete(state.mac_to_ip, mac)
        }
        Logger.info("🔓 RELEASE: #{Packet.ip_to_string(ip)} from #{mac}")
        {:reply, :ok, state}

      _ ->
        Logger.warning("⚠️  RELEASE: no active lease for #{mac} at #{Packet.ip_to_string(ip)}")
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:decline_offer, mac, ip}, _from, state) do
    Logger.warning("🚫 DECLINE: #{mac} declined #{Packet.ip_to_string(ip)} (address conflict detected)")
    # Mark IP as conflicted / quarantine briefly
    now = System.system_time(:second)
    lease = %Lease{
      ip: ip, mac: "DECLINED", hostname: nil,
      offered_at: now, expires_at: now + 300,
      state: :expired
    }
    state = %{state |
      leases: Map.put(state.leases, ip, lease),
      mac_to_ip: Map.delete(state.mac_to_ip, mac)
    }
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:get_lease_by_mac, mac}, _from, state) do
    result = case Map.get(state.mac_to_ip, mac) do
      nil -> nil
      ip -> Map.get(state.leases, ip)
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call(:list_leases, _from, state) do
    leases =
      state.leases
      |> Enum.map(fn {_ip, lease} -> lease end)
      |> Enum.sort_by(& &1.ip)
    {:reply, leases, state}
  end

  @impl true
  def handle_call({:add_reservation, mac, ip}, _from, state) do
    state = %{state | reserved: Map.put(state.reserved, mac, ip)}
    Logger.info("📌 Reservation added: #{mac} → #{Packet.ip_to_string(ip)}")
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:get_config, _from, state) do
    {:reply, state, state}
  end

  @impl true
  def handle_info(:check_expired_leases, state) do
    now = System.system_time(:second)
    {expired, state} = expire_leases(state, now)

    if expired > 0 do
      Logger.info("⏰ Lease expiry check: #{expired} lease(s) expired and reclaimed")
    end

    {:noreply, state}
  end

  # ---- Private helpers ----

  defp find_or_assign_ip(mac, state) do
    # 1. Check static reservation
    case Map.get(state.reserved, mac) do
      nil ->
        # 2. Check existing lease/offer
        case Map.get(state.mac_to_ip, mac) do
          nil -> allocate_new_ip(state, mac)
          ip  -> {:ok, ip, state}
        end
      reserved_ip ->
        {:ok, reserved_ip, state}
    end
  end

  defp allocate_new_ip(state, _mac) do
    start_int = ip_to_int(state.pool_start)
    end_int   = ip_to_int(state.pool_end)
    now       = System.system_time(:second)

    reserved_ips = Map.values(state.reserved) |> MapSet.new()

    result =
      Enum.find(start_int..end_int, fn n ->
        ip = int_to_ip(n)
        not MapSet.member?(reserved_ips, ip) and
        case Map.get(state.leases, ip) do
          nil -> true
          %Lease{state: s, expires_at: exp} when s in [:expired, :released] and exp < now -> true
          _ -> false
        end
      end)

    case result do
      nil -> {:error, :pool_exhausted}
      n   -> {:ok, int_to_ip(n), state}
    end
  end

  defp get_mac_ip(state, mac) do
    case Map.get(state.mac_to_ip, mac) do
      nil -> {:error, :not_found}
      ip  -> {:ok, ip}
    end
  end

  defp check_requested_ip(state, ip, _mac) do
    ip_int = ip_to_int(ip)
    start_int = ip_to_int(state.pool_start)
    end_int = ip_to_int(state.pool_end)

    ip_int >= start_int and ip_int <= end_int and
    case Map.get(state.leases, ip) do
      nil -> true
      %Lease{state: s} when s in [:expired, :released] -> true
      _ -> false
    end
  end

  defp put_lease(state, ip, mac, lease) do
    %{state |
      leases: Map.put(state.leases, ip, lease),
      mac_to_ip: Map.put(state.mac_to_ip, mac, ip)
    }
  end

  defp expire_leases(state, now) do
    {expired_count, new_leases, new_mac_to_ip} =
      Enum.reduce(state.leases, {0, state.leases, state.mac_to_ip}, fn
        {ip, %Lease{state: :active, expires_at: exp, mac: mac} = lease}, {count, leases, m2i}
        when exp < now ->
          Logger.debug("⏰ Lease expired: #{Packet.ip_to_string(ip)} (#{mac})")
          new_lease = %{lease | state: :expired}
          {count + 1, Map.put(leases, ip, new_lease), Map.delete(m2i, mac)}

        {ip, %Lease{state: :offered, expires_at: exp, mac: mac} = lease}, {count, leases, m2i}
        when exp < now ->
          Logger.debug("⏰ Offer expired: #{Packet.ip_to_string(ip)} (#{mac})")
          new_lease = %{lease | state: :expired}
          {count + 1, Map.put(leases, ip, new_lease), Map.delete(m2i, mac)}

        _, acc -> acc
      end)

    {expired_count, %{state | leases: new_leases, mac_to_ip: new_mac_to_ip}}
  end

  defp lease_options(state) do
    %{
      lease_time:       state.lease_time,
      renewal_time:     div(state.lease_time, 2),
      rebinding_time:   div(state.lease_time * 7, 8),
      subnet_mask:      state.subnet_mask,
      routers:          [state.router],
      dns_servers:      state.dns_servers,
      server_id:        state.server_ip,
      domain_name:      state.domain
    }
  end

  defp ip_to_int(<<a, b, c, d>>), do: a * 16_777_216 + b * 65_536 + c * 256 + d
  defp int_to_ip(n) do
    a = div(n, 16_777_216)
    b = div(rem(n, 16_777_216), 65_536)
    c = div(rem(n, 65_536), 256)
    d = rem(n, 256)
    <<a, b, c, d>>
  end

  defp format_hostname(nil), do: ""
  defp format_hostname(h), do: " (#{h})"

  defp format_xid(xid), do: "0x#{Integer.to_string(xid, 16)}"

  defp format_duration(secs) when secs >= 3600, do: "#{div(secs, 3600)}h#{div(rem(secs, 3600), 60)}m"
  defp format_duration(secs) when secs >= 60, do: "#{div(secs, 60)}m#{rem(secs, 60)}s"
  defp format_duration(secs), do: "#{secs}s"
end
