defmodule DhcpServer.Socket do
  @moduledoc """
  Handles raw UDP socket operations for DHCP.
  Listens on port 67 (server) and sends to port 68 (client) or broadcast.
  Binds to a specific network interface via SO_BINDTODEVICE to ensure
  broadcast replies go out on the correct interface.
  """
  use GenServer
  require Logger

  @dhcp_server_port 67
  @dhcp_client_port 68
  @broadcast_ip     {255, 255, 255, 255}

  # SO_BINDTODEVICE = 25 on Linux
  @so_bindtodevice 25
  @sol_socket      1

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Send a DHCP reply packet"
  def send_reply(packet_binary, dest_ip \\ @broadcast_ip) do
    GenServer.cast(__MODULE__, {:send, packet_binary, dest_ip})
  end

  @impl true
  def init(opts) do
    port      = Keyword.get(opts, :port, @dhcp_server_port)
    bind_ip   = Keyword.get(opts, :bind_ip, {0, 0, 0, 0})
    interface = Keyword.get(opts, :interface, nil)

    socket_opts = [
      :binary,
      {:active, true},
      {:reuseaddr, true},
      {:broadcast, true},
      {:ip, bind_ip}
    ]

    case :gen_udp.open(port, socket_opts) do
      {:ok, socket} ->
        :inet.setopts(socket, [{:broadcast, true}])

        # Bind to specific interface if provided (SO_BINDTODEVICE)
        # This ensures broadcast replies exit on the correct NIC
        case interface do
          nil -> :ok
          iface ->
            iface_bin = iface <> <<0>>  # null-terminated C string
            case :inet.setopts(socket, [{:raw, @sol_socket, @so_bindtodevice, iface_bin}]) do
              :ok ->
                Logger.info("🔗 Socket bound to interface: #{iface}")
              {:error, reason} ->
                Logger.warning("⚠️  Could not bind to interface #{iface}: #{inspect(reason)}")
            end
        end

        Logger.info("🔌 UDP socket open on port #{port} (bind: #{format_ip(bind_ip)}#{if interface, do: " dev=#{interface}", else: ""})")
        {:ok, %{socket: socket, port: port}}

      {:error, :eacces} ->
        Logger.error("❌ Cannot bind to port #{port} — requires root/CAP_NET_BIND_SERVICE")
        Logger.info("💡 Run with: sudo mix run --no-halt")
        {:stop, :eacces}

      {:error, reason} ->
        Logger.error("❌ Failed to open UDP socket: #{inspect(reason)}")
        {:stop, reason}
    end
  end

  @impl true
  def handle_cast({:send, packet_binary, dest_ip}, state) do
    case :gen_udp.send(state.socket, dest_ip, @dhcp_client_port, packet_binary) do
      :ok ->
        Logger.debug("📤 Sent #{byte_size(packet_binary)}B → #{format_ip(dest_ip)}:#{@dhcp_client_port}")
      {:error, reason} ->
        Logger.error("❌ Send error to #{format_ip(dest_ip)}: #{inspect(reason)}")
    end
    {:noreply, state}
  end

  @impl true
  def handle_info({:udp, _socket, src_ip, src_port, data}, state) do
    Logger.debug("📥 Received #{byte_size(data)}B from #{format_ip(src_ip)}:#{src_port}")
    DhcpServer.Handler.handle_packet(data, src_ip)
    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.debug("Socket received unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  defp format_ip({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp format_ip(ip), do: inspect(ip)
end
