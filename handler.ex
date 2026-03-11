defmodule DhcpServer.Handler do
  @moduledoc """
  DHCP message handler implementing the full DORA process:
    Discover → Offer → Request → Acknowledge
  Also handles: Release, Decline, Inform, Renewal, Rebinding
  """
  use GenServer
  require Logger

  alias DhcpServer.{Packet, LeaseManager, Socket}

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Process an incoming DHCP packet (called from Socket)"
  def handle_packet(data, src_ip) do
    GenServer.cast(__MODULE__, {:handle_packet, data, src_ip})
  end

  @impl true
  def init(_opts) do
    Logger.info("⚙️  DHCP Handler ready")
    {:ok, %{stats: %{discover: 0, request: 0, release: 0, decline: 0, inform: 0, errors: 0}}}
  end

  @impl true
  def handle_cast({:handle_packet, data, src_ip}, state) do
    state = case Packet.parse(data) do
      {:ok, packet} ->
        process_packet(packet, src_ip, state)

      {:error, reason} ->
        Logger.warning("⚠️  Malformed packet from #{format_ip(src_ip)}: #{reason}")
        update_stats(state, :errors)
    end
    {:noreply, state}
  end

  # ---- DHCP Message Dispatch ----

  defp process_packet(%Packet{message_type: type} = packet, src_ip, state) do
    mac = Packet.mac_to_string(packet.chaddr)
    hostname = get_hostname(packet)

    case type do
      t when t == Packet.discover() ->
        Logger.info("🔍 DHCPDISCOVER from #{mac}#{format_hostname(hostname)} [xid=#{format_xid(packet.xid)}]")
        handle_discover(packet, mac, hostname)
        update_stats(state, :discover)

      t when t == Packet.request() ->
        requested = get_requested_ip(packet)
        server_id = get_server_id(packet)
        Logger.info("📋 DHCPREQUEST from #{mac}#{format_hostname(hostname)} [xid=#{format_xid(packet.xid)}] requested=#{format_ip_bin(requested)} server=#{format_ip_bin(server_id)}")
        handle_request(packet, mac, hostname, src_ip)
        update_stats(state, :request)

      t when t == Packet.release() ->
        ip = packet.ciaddr
        Logger.info("🔓 DHCPRELEASE from #{mac} [ip=#{Packet.ip_to_string(ip)}]")
        handle_release(packet, mac)
        update_stats(state, :release)

      t when t == Packet.decline() ->
        ip = get_requested_ip(packet) || packet.ciaddr
        Logger.warning("🚫 DHCPDECLINE from #{mac} [ip=#{format_ip_bin(ip)}]")
        handle_decline(packet, mac)
        update_stats(state, :decline)

      t when t == Packet.inform() ->
        Logger.info("ℹ️  DHCPINFORM from #{mac} [ciaddr=#{Packet.ip_to_string(packet.ciaddr)}]")
        handle_inform(packet, mac)
        update_stats(state, :inform)

      nil ->
        Logger.warning("⚠️  DHCP packet with no message type from #{mac}")
        update_stats(state, :errors)

      other ->
        Logger.warning("⚠️  Unknown DHCP message type #{other} from #{mac}")
        update_stats(state, :errors)
    end
  end

  # ---- DHCPDISCOVER handler ----
  # Client broadcasts looking for a server → we reply with DHCPOFFER

  defp handle_discover(packet, mac, hostname) do
    config = LeaseManager.get_config()

    case LeaseManager.get_offer(mac, packet.xid, hostname) do
      {:ok, offered_ip, opts} ->
        reply =
          packet
          |> Packet.make_reply(config.server_ip)
          |> Map.put(:yiaddr, offered_ip)
          |> Map.update!(:options, fn o ->
            o
            |> Map.put(:message_type, Packet.offer())
            |> Map.merge(opts)
          end)

        send_reply(reply)

      {:error, :pool_exhausted} ->
        Logger.error("🚫 Pool exhausted — cannot offer IP to #{mac}")
        send_nak(packet, config.server_ip, "No addresses available")
    end
  end

  # ---- DHCPREQUEST handler ----
  # Client selects an offer and requests it → we reply with ACK or NAK
  # Also handles renewal (unicast) and rebinding (broadcast with ciaddr set)

  defp handle_request(packet, mac, hostname, _src_ip) do
    config = LeaseManager.get_config()

    # Determine which IP is being requested
    requested_ip =
      get_requested_ip(packet) ||
      (if packet.ciaddr != <<0,0,0,0>>, do: packet.ciaddr) ||
      case LeaseManager.get_lease_by_mac(mac) do
        nil -> nil
        lease -> lease.ip
      end

    # Check if this request is for our server
    server_id = get_server_id(packet)
    our_server = server_id == nil or server_id == config.server_ip

    cond do
      not our_server ->
        # Client chose another server — silently ignore
        Logger.debug("   Ignoring REQUEST for other server #{format_ip_bin(server_id)}")

      requested_ip == nil ->
        Logger.warning("❌ NAK: no IP in REQUEST from #{mac}")
        send_nak(packet, config.server_ip, "No requested IP")

      true ->
        case LeaseManager.confirm_lease(mac, requested_ip, packet.xid) do
          {:ok, ip, opts} ->
            reply =
              packet
              |> Packet.make_reply(config.server_ip)
              |> Map.put(:yiaddr, ip)
              |> Map.update!(:options, fn o ->
                o
                |> Map.put(:message_type, Packet.ack())
                |> Map.merge(opts)
              end)

            send_reply(reply)

          {:error, :nak} ->
            send_nak(packet, config.server_ip, "Lease not available")
        end
    end
  end

  # ---- DHCPRELEASE handler ----

  defp handle_release(packet, mac) do
    LeaseManager.release_lease(mac, packet.ciaddr)
  end

  # ---- DHCPDECLINE handler ----

  defp handle_decline(packet, mac) do
    ip = get_requested_ip(packet) || packet.ciaddr
    LeaseManager.decline_offer(mac, ip)
  end

  # ---- DHCPINFORM handler ----
  # Client has static IP but wants config options (DNS, etc.)

  defp handle_inform(packet, _mac) do
    config = LeaseManager.get_config()

    reply =
      packet
      |> Packet.make_reply(config.server_ip)
      |> Map.put(:yiaddr, <<0, 0, 0, 0>>)  # Do NOT assign IP
      |> Map.update!(:options, fn o ->
        o
        |> Map.put(:message_type, Packet.ack())
        |> Map.put(:subnet_mask, config.subnet_mask)
        |> Map.put(:routers, [config.router])
        |> Map.put(:dns_servers, config.dns_servers)
      end)

    # Send unicast to client's IP (ciaddr is set in INFORM)
    dest = ip_binary_to_tuple(packet.ciaddr)
    Socket.send_reply(Packet.build(reply), dest)
    Logger.info("✅ DHCPACK (INFORM) → #{Packet.ip_to_string(packet.ciaddr)}")
  end

  # ---- Helpers ----

  defp send_reply(reply_struct) do
    binary = Packet.build(reply_struct)
    # Broadcast if ciaddr is 0.0.0.0, unicast otherwise
    dest =
      if reply_struct.ciaddr == <<0, 0, 0, 0>> do
        {255, 255, 255, 255}
      else
        ip_binary_to_tuple(reply_struct.ciaddr)
      end
    Socket.send_reply(binary, dest)
  end

  defp send_nak(packet, server_ip, message) do
    Logger.warning("❌ Sending DHCPNAK to #{Packet.mac_to_string(packet.chaddr)}: #{message}")
    reply = %Packet{
      op:     Packet.bootreply(),
      htype:  packet.htype,
      hlen:   packet.hlen,
      hops:   0,
      xid:    packet.xid,
      secs:   0,
      flags:  0,
      ciaddr: <<0,0,0,0>>,
      yiaddr: <<0,0,0,0>>,
      siaddr: server_ip,
      giaddr: <<0,0,0,0>>,
      chaddr: packet.chaddr,
      sname:  :binary.copy(<<0>>, 64),
      file:   :binary.copy(<<0>>, 128),
      options: %{
        message_type: Packet.nak(),
        server_id: server_ip
      }
    }
    Socket.send_reply(Packet.build(reply), {255, 255, 255, 255})
  end

  defp get_hostname(packet), do: Map.get(packet.options, :hostname)
  defp get_requested_ip(packet), do: Map.get(packet.options, :requested_ip)
  defp get_server_id(packet), do: Map.get(packet.options, :server_id)

  defp format_hostname(nil), do: ""
  defp format_hostname(h), do: " (#{h})"

  defp format_xid(xid), do: "0x#{Integer.to_string(xid, 16)}"

  defp format_ip_bin(nil), do: "none"
  defp format_ip_bin(<<a, b, c, d>>), do: "#{a}.#{b}.#{c}.#{d}"
  defp format_ip_bin({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp format_ip_bin(other), do: inspect(other)

  defp format_ip({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp format_ip(other), do: inspect(other)

  defp ip_binary_to_tuple(<<a, b, c, d>>), do: {a, b, c, d}

  defp update_stats(state, key) do
    put_in(state, [:stats, key], Map.get(state.stats, key, 0) + 1)
  end
end
