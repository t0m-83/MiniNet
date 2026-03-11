defmodule DhcpServer.Packet do
  @moduledoc """
  DHCP Packet parsing and building.
  Implements RFC 2131 DHCP packet format.
  """

  # DHCP Message Types
  @dhcp_discover 1
  @dhcp_offer    2
  @dhcp_request  3
  @dhcp_decline  4
  @dhcp_ack      5
  @dhcp_nak      6
  @dhcp_release  7
  @dhcp_inform   8

  # DHCP Options
  @opt_subnet_mask        1
  @opt_router             3
  @opt_dns_servers        6
  @opt_hostname          12
  @opt_domain_name       15
  @opt_broadcast_addr    28
  @opt_requested_ip      50
  @opt_lease_time        51
  @opt_message_type      53
  @opt_server_id         54
  @opt_param_req_list    55
  @opt_renewal_time      58
  @opt_rebinding_time    59
  @opt_client_id         61
  @opt_end              255

  # Boot operations
  @bootrequest 1
  @bootreply   2

  # Magic cookie (RFC 2131)
  @magic_cookie <<99, 130, 83, 99>>

  defstruct [
    :op, :htype, :hlen, :hops,
    :xid, :secs, :flags,
    :ciaddr, :yiaddr, :siaddr, :giaddr,
    :chaddr, :sname, :file,
    :options, :message_type, :raw_options
  ]

  def message_type_name(1), do: "DHCPDISCOVER"
  def message_type_name(2), do: "DHCPOFFER"
  def message_type_name(3), do: "DHCPREQUEST"
  def message_type_name(4), do: "DHCPDECLINE"
  def message_type_name(5), do: "DHCPACK"
  def message_type_name(6), do: "DHCPNAK"
  def message_type_name(7), do: "DHCPRELEASE"
  def message_type_name(8), do: "DHCPINFORM"
  def message_type_name(n), do: "UNKNOWN(#{n})"

  @doc "Parse raw UDP payload into a DHCP packet struct"
  def parse(<<
    op::8, htype::8, hlen::8, hops::8,
    xid::32,
    secs::16, flags::16,
    ciaddr::binary-size(4),
    yiaddr::binary-size(4),
    siaddr::binary-size(4),
    giaddr::binary-size(4),
    chaddr::binary-size(16),
    sname::binary-size(64),
    file::binary-size(128),
    @magic_cookie,
    options_bin::binary
  >>) do
    options = parse_options(options_bin, %{})
    message_type = Map.get(options, :message_type)

    {:ok, %__MODULE__{
      op: op,
      htype: htype,
      hlen: hlen,
      hops: hops,
      xid: xid,
      secs: secs,
      flags: flags,
      ciaddr: ciaddr,
      yiaddr: yiaddr,
      siaddr: siaddr,
      giaddr: giaddr,
      chaddr: chaddr,
      sname: sname,
      file: file,
      options: options,
      message_type: message_type
    }}
  end

  def parse(_), do: {:error, :invalid_packet}

  @doc "Build a DHCP reply packet"
  def build(packet) do
    options_bin = encode_options(packet.options)
    flags = Map.get(packet, :flags, 0) || 0

    <<
      packet.op::8,
      packet.htype::8,
      packet.hlen::8,
      packet.hops::8,
      packet.xid::32,
      0::16,        # secs
      flags::16,    # flags (0x8000 = broadcast bit)
      packet.ciaddr::binary,
      packet.yiaddr::binary,
      packet.siaddr::binary,
      packet.giaddr::binary,
      packet.chaddr::binary,
      :binary.copy(<<0>>, 64)::binary,   # sname
      :binary.copy(<<0>>, 128)::binary,  # file
      @magic_cookie::binary,
      options_bin::binary
    >>
  end

  @doc "Create a base DHCP reply from a request"
  def make_reply(request, server_ip) do
    %__MODULE__{
      op: @bootreply,
      htype: request.htype,
      hlen: request.hlen,
      hops: 0,
      xid: request.xid,
      secs: 0,
      flags: 0,
      ciaddr: <<0, 0, 0, 0>>,
      yiaddr: <<0, 0, 0, 0>>,
      siaddr: server_ip,
      giaddr: <<0, 0, 0, 0>>,
      chaddr: request.chaddr,
      sname: :binary.copy(<<0>>, 64),
      file: :binary.copy(<<0>>, 128),
      options: %{server_id: server_ip}
    }
  end

  @doc "Extract MAC address as string from chaddr field"
  def mac_to_string(chaddr) do
    chaddr
    |> :binary.bin_to_list()
    |> Enum.take(6)
    |> Enum.map(&Integer.to_string(&1, 16))
    |> Enum.map(&String.pad_leading(&1, 2, "0"))
    |> Enum.join(":")
    |> String.downcase()
  end

  @doc "Convert IP tuple/binary to readable string"
  def ip_to_string(<<a, b, c, d>>), do: "#{a}.#{b}.#{c}.#{d}"
  def ip_to_string({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"

  @doc "Convert IP string to binary"
  def ip_to_binary(ip_str) when is_binary(ip_str) do
    ip_str
    |> String.split(".")
    |> Enum.map(&String.to_integer/1)
    |> :erlang.list_to_binary()
  end

  def ip_to_binary({a, b, c, d}), do: <<a, b, c, d>>

  # ---- Option parsing ----

  defp parse_options(<<>>, acc), do: acc
  defp parse_options(<<@opt_end, _rest::binary>>, acc), do: acc
  defp parse_options(<<0, rest::binary>>, acc), do: parse_options(rest, acc)  # pad

  defp parse_options(<<@opt_message_type, 1, type::8, rest::binary>>, acc) do
    parse_options(rest, Map.put(acc, :message_type, type))
  end

  defp parse_options(<<@opt_subnet_mask, 4, a, b, c, d, rest::binary>>, acc) do
    parse_options(rest, Map.put(acc, :subnet_mask, <<a, b, c, d>>))
  end

  defp parse_options(<<@opt_router, len::8, data::binary-size(len), rest::binary>>, acc) do
    routers = for <<a, b, c, d <- data>>, do: <<a, b, c, d>>
    parse_options(rest, Map.put(acc, :routers, routers))
  end

  defp parse_options(<<@opt_dns_servers, len::8, data::binary-size(len), rest::binary>>, acc) do
    dns = for <<a, b, c, d <- data>>, do: <<a, b, c, d>>
    parse_options(rest, Map.put(acc, :dns_servers, dns))
  end

  defp parse_options(<<@opt_requested_ip, 4, a, b, c, d, rest::binary>>, acc) do
    parse_options(rest, Map.put(acc, :requested_ip, <<a, b, c, d>>))
  end

  defp parse_options(<<@opt_lease_time, 4, t::32, rest::binary>>, acc) do
    parse_options(rest, Map.put(acc, :lease_time, t))
  end

  defp parse_options(<<@opt_server_id, 4, a, b, c, d, rest::binary>>, acc) do
    parse_options(rest, Map.put(acc, :server_id, <<a, b, c, d>>))
  end

  defp parse_options(<<@opt_hostname, len::8, data::binary-size(len), rest::binary>>, acc) do
    parse_options(rest, Map.put(acc, :hostname, data))
  end

  defp parse_options(<<@opt_client_id, len::8, data::binary-size(len), rest::binary>>, acc) do
    parse_options(rest, Map.put(acc, :client_id, data))
  end

  defp parse_options(<<@opt_param_req_list, len::8, data::binary-size(len), rest::binary>>, acc) do
    params = :binary.bin_to_list(data)
    parse_options(rest, Map.put(acc, :param_request_list, params))
  end

  defp parse_options(<<_code::8, len::8, _data::binary-size(len), rest::binary>>, acc) do
    parse_options(rest, acc)
  end

  defp parse_options(_, acc), do: acc

  # ---- Option encoding ----

  defp encode_options(opts) do
    parts =
      [
        encode_message_type(Map.get(opts, :message_type)),
        encode_server_id(Map.get(opts, :server_id)),
        encode_lease_time(Map.get(opts, :lease_time)),
        encode_renewal_time(Map.get(opts, :renewal_time)),
        encode_rebinding_time(Map.get(opts, :rebinding_time)),
        encode_subnet_mask(Map.get(opts, :subnet_mask)),
        encode_router(Map.get(opts, :routers)),
        encode_dns(Map.get(opts, :dns_servers)),
        encode_domain_name(Map.get(opts, :domain_name)),
        encode_broadcast(Map.get(opts, :broadcast_address)),
        <<@opt_end>>
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.join()

    parts
  end

  defp encode_message_type(nil), do: nil
  defp encode_message_type(t), do: <<@opt_message_type, 1, t>>

  defp encode_server_id(nil), do: nil
  defp encode_server_id(ip), do: <<@opt_server_id, 4>> <> ip

  defp encode_lease_time(nil), do: nil
  defp encode_lease_time(t), do: <<@opt_lease_time, 4, t::32>>

  defp encode_renewal_time(nil), do: nil
  defp encode_renewal_time(t), do: <<@opt_renewal_time, 4, t::32>>

  defp encode_rebinding_time(nil), do: nil
  defp encode_rebinding_time(t), do: <<@opt_rebinding_time, 4, t::32>>

  defp encode_subnet_mask(nil), do: nil
  defp encode_subnet_mask(mask), do: <<@opt_subnet_mask, 4>> <> mask

  defp encode_router(nil), do: nil
  defp encode_router([]), do: nil
  defp encode_router(routers) do
    data = Enum.join(routers)
    <<@opt_router, byte_size(data)>> <> data
  end

  defp encode_dns(nil), do: nil
  defp encode_dns([]), do: nil
  defp encode_dns(servers) do
    data = Enum.join(servers)
    <<@opt_dns_servers, byte_size(data)>> <> data
  end

  defp encode_broadcast(nil), do: nil
  defp encode_broadcast(ip), do: <<@opt_broadcast_addr, 4>> <> ip

  defp encode_domain_name(nil), do: nil
  defp encode_domain_name(name) do
    <<@opt_domain_name, byte_size(name)>> <> name
  end

  # Message type constants for external use
  def discover, do: @dhcp_discover
  def offer,    do: @dhcp_offer
  def request,  do: @dhcp_request
  def decline,  do: @dhcp_decline
  def ack,      do: @dhcp_ack
  def nak,      do: @dhcp_nak
  def release,  do: @dhcp_release
  def inform,   do: @dhcp_inform
  def bootrequest, do: @bootrequest
  def bootreply,   do: @bootreply
end
