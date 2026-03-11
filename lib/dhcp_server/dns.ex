defmodule DhcpServer.Dns do
  @moduledoc """
  Embedded DNS server (UDP port 53).

  Résout automatiquement les noms des clients DHCP actifs.
  Les requêtes non-locales sont forwardées vers un resolver upstream (ex: 8.8.8.8).

  Fonctionnalités :
  - Résolution A  : hostname → IP  (ex: debian → 192.168.1.100)
  - Résolution PTR : IP → hostname  (ex: 100.1.168.192.in-addr.arpa → debian.home.local)
  - Forward des requêtes externes vers upstream DNS
  - TTL dynamique basé sur le temps restant du bail DHCP
  """
  use GenServer
  require Logger
  import Bitwise

  alias DhcpServer.{LeaseManager, Packet}

  @dns_port     53
  @upstream_dns {{8, 8, 8, 8}, 53}
  @default_ttl  300

  # DNS opcodes / rcodes
  @rcode_ok       0
  @rcode_nxdomain 3
  @rcode_servfail 2
  @rcode_refused  5

  # DNS record types
  @type_a     1
  @type_ns    2
  @type_cname 5
  @type_ptr   12
  @type_aaaa  28
  @type_any   255

  @class_in 1

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  # ---- GenServer ----

  @impl true
  def init(opts) do
    port      = Keyword.get(opts, :port, @dns_port)
    domain    = Keyword.get(opts, :domain, "home.local")
    interface = Keyword.get(opts, :interface, nil)
    upstream  = Keyword.get(opts, :upstream, @upstream_dns)
    bind_ip   = case Keyword.get(opts, :bind_ip) do
      nil       -> {0, 0, 0, 0}
      <<a,b,c,d>> -> {a, b, c, d}
      tuple     -> tuple
    end

    socket_opts = [
      :binary,
      {:active, true},
      {:reuseaddr, true},
      {:ip, bind_ip}
    ]

    case :gen_udp.open(port, socket_opts) do
      {:ok, socket} ->
        if interface do
          iface_bin = interface <> <<0>>
          case :inet.setopts(socket, [{:raw, 1, 25, iface_bin}]) do
            :ok -> Logger.info("🔗 DNS socket bound to interface: #{interface}")
            {:error, r} -> Logger.warning("⚠️  DNS interface bind failed: #{inspect(r)}")
          end
        end

        bind_str = "#{format_ip(bind_ip)}:#{port}"
        Logger.info("🌐 DNS server listening on #{bind_str} — domain: .#{domain}")
        Logger.info("   Upstream resolver: #{format_upstream(upstream)}")

        {:ok, %{
          socket:    socket,
          port:      port,
          domain:    domain,
          upstream:  upstream,
          pending:   %{},
          query_count: 0,
          hit_count:   0
        }}

      {:error, :eacces} ->
        Logger.error("❌ Cannot bind DNS to port #{port} — requires root")
        {:stop, :eacces}

      {:error, :eaddrinuse} ->
        Logger.error("❌ DNS port #{port} already in use (systemd-resolved?)")
        Logger.error("   Fix: sudo systemctl stop systemd-resolved")
        Logger.error("   Or:  sudo systemctl disable --now systemd-resolved")
        {:stop, :eaddrinuse}

      {:error, reason} ->
        Logger.error("❌ DNS socket error: #{inspect(reason)}")
        {:stop, reason}
    end
  end

  @impl true
  def handle_info({:udp, _sock, src_ip, src_port, data}, state) do
    state = handle_dns_packet(data, src_ip, src_port, state)
    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.debug("DNS unexpected msg: #{inspect(msg)}")
    {:noreply, state}
  end

  # ---- DNS Packet Dispatch ----

  defp handle_dns_packet(data, src_ip, src_port, state) do
    case parse_dns(data) do
      {:ok, msg} ->
        state = %{state | query_count: state.query_count + 1}

        cond do
          # It's a response from upstream — relay it back to original client
          msg.qr == 1 ->
            relay_upstream_response(msg, data, src_ip, src_port, state)

          # It's a query from a client
          msg.qr == 0 ->
            handle_query(msg, data, src_ip, src_port, state)

          true -> state
        end

      {:error, reason} ->
        Logger.warning("⚠️  DNS parse error from #{format_ip(src_ip)}: #{reason}")
        state
    end
  end

  # ---- Query Handler ----

  defp handle_query(msg, raw_data, src_ip, src_port, state) do
    question = List.first(msg.questions)

    if question do
      qname = question.name
      qtype = question.type
      Logger.debug("🔎 DNS query [#{format_ip(src_ip)}] #{qtype_name(qtype)} #{qname}")

      cond do
        # PTR query: reverse lookup (x.x.x.x.in-addr.arpa)
        qtype == @type_ptr and String.ends_with?(qname, ".in-addr.arpa") ->
          handle_ptr_query(msg, qname, src_ip, src_port, state)

        # AAAA query for local domain — répondre NXDOMAIN immédiatement (pas d'IPv6)
        qtype == @type_aaaa and is_local?(qname, state.domain) ->
          Logger.debug("   ↳ AAAA local → NXDOMAIN immédiat: #{qname}")
          reply = build_reply(msg, @rcode_nxdomain, [])
          send_dns(state.socket, src_ip, src_port, reply)
          state

        # A query for our local domain
        qtype in [@type_a, @type_any] and is_local?(qname, state.domain) ->
          handle_a_query(msg, qname, src_ip, src_port, state)

        # Forward everything else upstream
        true ->
          forward_upstream(msg, raw_data, src_ip, src_port, state)
      end
    else
      state
    end
  end

  # ---- A Record (hostname → IP) ----

  defp handle_a_query(msg, qname, src_ip, src_port, state) do
    hostname = extract_hostname(qname, state.domain)
    leases = LeaseManager.list_leases()

    match =
      Enum.find(leases, fn lease ->
        lease.state == :active and lease_matches_hostname(lease, hostname)
      end)

    case match do
      nil ->
        Logger.debug("   ↳ NXDOMAIN: #{qname}")
        reply = build_reply(msg, @rcode_nxdomain, [])
        send_dns(state.socket, src_ip, src_port, reply)
        state

      lease ->
        ttl = max(1, lease.expires_at - System.system_time(:second))
        ttl = min(ttl, @default_ttl)
        ip_str = Packet.ip_to_string(lease.ip)
        Logger.info("✅ DNS A #{qname} → #{ip_str} [ttl=#{ttl}s] (#{format_ip(src_ip)})")

        answer = %{
          name:  qname,
          type:  @type_a,
          class: @class_in,
          ttl:   ttl,
          rdata: lease.ip
        }
        reply = build_reply(msg, @rcode_ok, [answer])
        send_dns(state.socket, src_ip, src_port, reply)
        %{state | hit_count: state.hit_count + 1}
    end
  end

  # ---- PTR Record (IP → hostname) ----

  defp handle_ptr_query(msg, qname, src_ip, src_port, state) do
    ip_bin = arpa_to_ip(qname)
    leases = LeaseManager.list_leases()

    match =
      Enum.find(leases, fn lease ->
        lease.state == :active and lease.ip == ip_bin
      end)

    case match do
      nil ->
        reply = build_reply(msg, @rcode_nxdomain, [])
        send_dns(state.socket, src_ip, src_port, reply)
        state

      lease ->
        ttl = max(1, min(lease.expires_at - System.system_time(:second), @default_ttl))
        fqdn = "#{lease.hostname || Packet.ip_to_string(lease.ip)}.#{state.domain}"
        ip_str = Packet.ip_to_string(lease.ip)
        Logger.info("✅ DNS PTR #{ip_str} → #{fqdn} [ttl=#{ttl}s]")

        answer = %{
          name:  qname,
          type:  @type_ptr,
          class: @class_in,
          ttl:   ttl,
          rdata: fqdn
        }
        reply = build_reply(msg, @rcode_ok, [answer])
        send_dns(state.socket, src_ip, src_port, reply)
        %{state | hit_count: state.hit_count + 1}
    end
  end

  # ---- Upstream Forwarding ----

  defp forward_upstream(msg, raw_data, src_ip, src_port, state) do
    {upstream_ip, upstream_port} = state.upstream

    # Use a new ID to track which client to reply to
    new_id = :rand.uniform(65535)
    # Rewrite the ID in the raw packet
    <<_old_id::16, rest::binary>> = raw_data
    rewritten = <<new_id::16, rest::binary>>

    case :gen_udp.send(state.socket, upstream_ip, upstream_port, rewritten) do
      :ok ->
        qname = (List.first(msg.questions) || %{name: "?"}).name
        Logger.debug("⏩ DNS forward #{qname} → #{format_ip(upstream_ip)} [id=#{new_id}]")
        new_pending = Map.put(state.pending, new_id, {src_ip, src_port, msg.id})
        %{state | pending: new_pending}

      {:error, reason} ->
        Logger.warning("⚠️  DNS forward failed: #{inspect(reason)}")
        reply = build_reply(msg, @rcode_servfail, [])
        send_dns(state.socket, src_ip, src_port, reply)
        state
    end
  end

  defp relay_upstream_response(_msg, raw_data, _src_ip, _src_port, state) do
    <<response_id::16, rest::binary>> = raw_data

    case Map.pop(state.pending, response_id) do
      {nil, _} ->
        # Unknown/unsolicited response — ignore
        state

      {{client_ip, client_port, original_id}, new_pending} ->
        # Restore original client ID and relay
        relayed = <<original_id::16, rest::binary>>
        send_dns(state.socket, client_ip, client_port, relayed)
        Logger.debug("⏪ DNS relayed upstream response → #{format_ip(client_ip)}")
        %{state | pending: new_pending}
    end
  end

  # ---- DNS Wire Format Parser ----

  defp parse_dns(<<id::16, flags::16, qdcount::16, ancount::16, nscount::16, arcount::16, rest::binary>>) do
    qr     = flags >>> 15 &&& 1
    opcode = flags >>> 11 &&& 0xF
    rcode  = flags &&& 0xF

    {questions, _rest2} = parse_questions(rest, qdcount, rest)

    {:ok, %{
      id:        id,
      qr:        qr,
      opcode:    opcode,
      rcode:     rcode,
      qdcount:   qdcount,
      ancount:   ancount,
      nscount:   nscount,
      arcount:   arcount,
      questions: questions
    }}
  end

  defp parse_dns(_), do: {:error, :invalid}

  defp parse_questions(bin, 0, _full), do: {[], bin}
  defp parse_questions(bin, count, full) do
    {name, rest} = parse_name(bin, full)
    case rest do
      <<type::16, class::16, rest2::binary>> ->
        q = %{name: name, type: type, class: class}
        {more, final} = parse_questions(rest2, count - 1, full)
        {[q | more], final}
      _ ->
        {[], bin}
    end
  end

  # DNS name parsing with pointer compression support
  defp parse_name(bin, full), do: parse_name(bin, full, [])

  defp parse_name(<<0, rest::binary>>, _full, parts) do
    {Enum.join(Enum.reverse(parts), "."), rest}
  end

  defp parse_name(<<0b11::2, offset::14, rest::binary>>, full, parts) do
    # Pointer compression
    <<_::binary-size(offset), ptr_data::binary>> = full
    {name_from_ptr, _} = parse_name(ptr_data, full, parts)
    {name_from_ptr, rest}
  end

  defp parse_name(<<len::8, label::binary-size(len), rest::binary>>, full, parts) do
    parse_name(rest, full, [label | parts])
  end

  defp parse_name(_, _full, parts) do
    {Enum.join(Enum.reverse(parts), "."), <<>>}
  end

  # ---- DNS Wire Format Builder ----

  defp build_reply(query, rcode, answers) do
    flags = build_flags(1, 0, 1, 0, rcode)
    ancount = length(answers)
    header = <<query.id::16, flags::16, length(query.questions)::16, ancount::16, 0::16, 0::16>>

    questions_bin =
      Enum.map(query.questions, fn q ->
        encode_name(q.name) <> <<q.type::16, q.class::16>>
      end)
      |> Enum.join()

    answers_bin =
      Enum.map(answers, &encode_answer/1)
      |> Enum.join()

    header <> questions_bin <> answers_bin
  end

  defp build_flags(qr, opcode, aa, rd, rcode) do
    qr    <<< 15 |||
    opcode <<< 11 |||
    aa    <<< 10 |||
    0     <<< 9  |||  # tc
    rd    <<< 8  |||
    0     <<< 7  |||  # ra
    rcode
  end

  defp encode_answer(%{type: @type_a} = ans) do
    encode_name(ans.name) <>
    <<@type_a::16, @class_in::16, ans.ttl::32, 4::16>> <>
    ans.rdata
  end

  defp encode_answer(%{type: @type_ptr} = ans) do
    rdata_bin = encode_name(ans.rdata)
    encode_name(ans.name) <>
    <<@type_ptr::16, @class_in::16, ans.ttl::32, byte_size(rdata_bin)::16>> <>
    rdata_bin
  end

  defp encode_name(name) do
    name
    |> String.split(".")
    |> Enum.map(fn label ->
      len = byte_size(label)
      <<len::8, label::binary>>
    end)
    |> Enum.join()
    |> Kernel.<>(<<0>>)
  end

  # ---- Helpers ----

  defp send_dns(socket, ip, port, data) do
    case :gen_udp.send(socket, ip, port, data) do
      :ok -> :ok
      {:error, reason} ->
        Logger.error("❌ DNS send error to #{format_ip(ip)}: #{inspect(reason)}")
    end
  end

  defp is_local?(qname, domain) do
    String.ends_with?(String.downcase(qname), "." <> domain) or
    String.ends_with?(String.downcase(qname), "." <> domain <> ".") or
    not String.contains?(qname, ".")
  end

  defp extract_hostname(qname, domain) do
    qname
    |> String.replace_suffix("." <> domain, "")
    |> String.replace_suffix("." <> domain <> ".", "")
    |> String.downcase()
  end

  defp lease_matches_hostname(lease, hostname) do
    h = String.downcase(hostname)
    (lease.hostname && String.downcase(lease.hostname) == h) or
    Packet.ip_to_string(lease.ip) == hostname
  end

  # Convert x.x.x.x.in-addr.arpa to IP binary
  defp arpa_to_ip(qname) do
    qname
    |> String.replace_suffix(".in-addr.arpa", "")
    |> String.replace_suffix(".in-addr.arpa.", "")
    |> String.split(".")
    |> Enum.reverse()
    |> Enum.map(&String.to_integer/1)
    |> :erlang.list_to_binary()
  rescue
    _ -> <<0, 0, 0, 0>>
  end

  defp qtype_name(1),   do: "A"
  defp qtype_name(12),  do: "PTR"
  defp qtype_name(28),  do: "AAAA"
  defp qtype_name(255), do: "ANY"
  defp qtype_name(n),   do: "TYPE#{n}"

  defp format_ip({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp format_ip(other), do: inspect(other)

  defp format_upstream({{a, b, c, d}, port}), do: "#{a}.#{b}.#{c}.#{d}:#{port}"
end
