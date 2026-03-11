defmodule DhcpServer.StatusReporter do
  @moduledoc """
  Periodically logs a lease table summary to the console.
  Provides real-time visibility into server state.
  """
  use GenServer
  require Logger

  alias DhcpServer.{LeaseManager, Packet}

  @report_interval 30_000  # Print status every 30 seconds

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Force an immediate status print"
  def print_status do
    GenServer.cast(__MODULE__, :print_status)
  end

  @impl true
  def init(_opts) do
    :timer.send_interval(@report_interval, :report)
    {:ok, %{}}
  end

  @impl true
  def handle_cast(:print_status, state) do
    do_print_status()
    {:noreply, state}
  end

  @impl true
  def handle_info(:report, state) do
    leases = LeaseManager.list_leases()
    active = Enum.count(leases, &(&1.state == :active))

    if active > 0 do
      do_print_status()
    end

    {:noreply, state}
  end

  defp do_print_status do
    leases = LeaseManager.list_leases()
    config = LeaseManager.get_config()
    now = System.system_time(:second)

    active   = Enum.filter(leases, &(&1.state == :active))
    offered  = Enum.filter(leases, &(&1.state == :offered))
    expired  = Enum.filter(leases, &(&1.state == :expired))
    released = Enum.filter(leases, &(&1.state == :released))

    pool_size = ip_pool_size(config.pool_start, config.pool_end)
    used = length(active) + length(offered)

    Logger.info(String.duplicate("─", 72))
    Logger.info("📊 DHCP SERVER STATUS — #{format_time()}")
    Logger.info("   Server IP  : #{Packet.ip_to_string(config.server_ip)}")
    Logger.info("   Pool       : #{Packet.ip_to_string(config.pool_start)} → #{Packet.ip_to_string(config.pool_end)} (#{pool_size} addresses)")
    Logger.info("   Used/Free  : #{used}/#{pool_size - used} (#{pct(used, pool_size)}% utilization)")
    Logger.info("   Leases     : #{length(active)} active | #{length(offered)} offered | #{length(expired)} expired | #{length(released)} released")

    if length(active) > 0 do
      Logger.info(String.duplicate("─", 72))
      Logger.info("   #{String.pad_trailing("IP ADDRESS", 16)} #{String.pad_trailing("MAC ADDRESS", 18)} #{String.pad_trailing("EXPIRES IN", 12)} HOSTNAME")

      Enum.each(active, fn lease ->
        remaining    = max(0, lease.expires_at - now)
        ip_str       = lease.ip |> Packet.ip_to_string() |> String.pad_trailing(16)
        mac_str      = String.pad_trailing(lease.mac, 18)
        dur_str      = lease.expires_at |> then(fn _ -> format_duration(remaining) end) |> String.pad_trailing(12)
        hostname_str = lease.hostname || "—"
        Logger.info("   #{ip_str} #{mac_str} #{dur_str} #{hostname_str}")
      end)
    end

    Logger.info(String.duplicate("─", 72))
  end

  defp ip_pool_size(start_ip, end_ip) do
    <<a, b, c, d>> = start_ip
    <<e, f, g, h>> = end_ip
    s = a * 16_777_216 + b * 65_536 + c * 256 + d
    e2 = e * 16_777_216 + f * 65_536 + g * 256 + h
    e2 - s + 1
  end

  defp format_time do
    {{y, m, d}, {hh, mm, ss}} = :calendar.local_time()
    "#{y}-#{pad(m)}-#{pad(d)} #{pad(hh)}:#{pad(mm)}:#{pad(ss)}"
  end

  defp pad(n), do: String.pad_leading(Integer.to_string(n), 2, "0")

  defp format_duration(secs) when secs >= 3600 do
    h = div(secs, 3600)
    m = div(rem(secs, 3600), 60)
    "#{h}h #{pad(m)}m"
  end
  defp format_duration(secs) when secs >= 60 do
    "#{div(secs, 60)}m #{pad(rem(secs, 60))}s"
  end
  defp format_duration(secs), do: "#{secs}s"

  defp pct(0, _), do: 0
  defp pct(n, total), do: Float.round(n / total * 100, 1)
end
