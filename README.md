# MiniNet

**MiniNet** est un serveur DHCP et DNS intégré, écrit en Elixir avec supervision OTP.  
Il distribue des adresses IP, résout les noms d'hôtes des clients et forward les requêtes externes — le tout avec des logs en temps réel dans la console.

---

## Fonctionnalités

### DHCP (RFC 2131)

| Message | Rôle |
|---|---|
| `DHCPDISCOVER` | Le client cherche un serveur DHCP sur le réseau |
| `DHCPOFFER` | MiniNet propose une adresse IP disponible |
| `DHCPREQUEST` | Le client confirme qu'il accepte l'offre |
| `DHCPACK` | MiniNet confirme et attribue le bail |
| `DHCPNAK` | MiniNet refuse (IP invalide, pool épuisé…) |
| `DHCPRELEASE` | Le client libère son adresse IP |
| `DHCPDECLINE` | Le client signale un conflit d'adresse |
| `DHCPINFORM` | Config réseau pour les clients en IP statique |

### DNS

- **Résolution directe** : `debian.home.local` → `192.168.1.100`
- **Résolution inverse** : `192.168.1.100` → `debian.home.local` (PTR)
- **Réponse NXDOMAIN immédiate** pour AAAA local (évite les délais IPv6)
- **Forward transparent** vers un resolver upstream (ex: `8.8.8.8`) pour les domaines externes
- **TTL dynamique** basé sur le temps restant du bail DHCP

### Autres
- Réservations statiques MAC → IP
- Expiration et reclamation automatique des baux
- Tableau de baux périodique toutes les 30s
- API IEx pour administrer le serveur à chaud

---

## Architecture OTP

```
DhcpServer.Application  (Supervisor)
├── DhcpServer.LeaseManager    — Pool IP, cycle de vie des baux, réservations
├── DhcpServer.Handler         — Machine à états DHCP (DORA)
├── DhcpServer.Socket          — Socket UDP port 67
├── DhcpServer.Dns             — Serveur DNS port 53 + forward upstream
└── DhcpServer.StatusReporter  — Logs périodiques du tableau des baux
```

---

## Installation

```bash
# Debian / Ubuntu
sudo apt-get install elixir

# macOS
brew install elixir

# Récupérer les dépendances
mix deps.get
```

---

## Configuration

Toute la configuration se trouve dans un seul fichier :

```
lib/dhcp_server/application.ex
```

Il contient deux sections à modifier : `load_config/0` pour le DHCP et le bloc `DhcpServer.Dns` pour le DNS et l'interface réseau.

---

### 1. Réseau et DHCP

Dans la fonction `load_config/0` :

```elixir
defp load_config do
  %{
    # IP du serveur MiniNet sur le réseau local
    # Doit correspondre à l'IP du bridge (virbr2, br0, etc.)
    server_ip:   ip("192.168.1.1"),

    # Plage d'adresses IP à distribuer aux clients
    pool_start:  ip("192.168.1.100"),
    pool_end:    ip("192.168.1.200"),

    # Masque de sous-réseau envoyé aux clients
    subnet_mask: ip("255.255.255.0"),

    # Passerelle par défaut annoncée aux clients
    router:      ip("192.168.1.1"),

    # Serveurs DNS annoncés aux clients
    # Mettre MiniNet en premier pour la résolution locale,
    # puis un serveur public en fallback
    dns_servers: [ip("192.168.1.1"), ip("8.8.8.8")],

    # Domaine de recherche local
    # Permet de faire `ping debian` au lieu de `ping debian.home.local`
    domain: "home.local",

    # Durée des baux en secondes
    # 86400 = 24h | 43200 = 12h | 3600 = 1h
    lease_time: 86_400,

    # Réservations statiques : ce client obtiendra toujours cette IP
    # Format : "adresse:mac" => ip("x.x.x.x")
    reservations: %{
      "aa:bb:cc:dd:ee:ff" => ip("192.168.1.50"),
      "11:22:33:44:55:66" => ip("192.168.1.51")
    }
  }
end
```

---

### 2. Interface réseau

Dans la fonction `start/2`, deux entrées définissent l'interface réseau à utiliser.  
Il s'agit du nom du bridge Linux sur lequel les clients sont connectés.

```elixir
# DHCP — écoute sur toutes les IPs mais force la sortie sur l'interface
{DhcpServer.Socket, [
  port: 67,
  bind_ip: {0, 0, 0, 0},
  interface: "virbr2"       # ← nom du bridge Linux
]},

# DNS — bindé sur l'IP du serveur pour éviter les conflits
{DhcpServer.Dns, [
  port: 53,
  bind_ip: {192, 168, 1, 1},  # ← IP du serveur (même que server_ip, en tuple)
  domain: config.domain,
  interface: "virbr2",         # ← même interface que le DHCP
  upstream: {{8, 8, 8, 8}, 53} # ← resolver upstream pour les domaines externes
]},
```

**Comment trouver le nom de l'interface :**

```bash
# Lister tous les bridges disponibles
ip link show type bridge

# Pour libvirt : trouver le bridge associé à un réseau
virsh net-info <nom_du_réseau>

# Vérifier que la VM est bien attachée au bridge
ip link show master virbr2

# Si la VM n'est pas attachée, la rattacher manuellement
sudo ip link set vnet0 master virbr2
```

> **Note libvirt** : libvirt lance automatiquement `dnsmasq` sur chaque réseau virtuel.
> Il faut le désactiver pour laisser MiniNet prendre la main.
> Dans `virsh net-edit <nom_du_réseau>`, ajouter dans la balise `<network>` :
> ```xml
> <dns enable='no'/>
> ```
> Puis supprimer le bloc `<dhcp>...</dhcp>` si présent, et redémarrer le réseau :
> ```bash
> virsh net-destroy <nom_du_réseau>
> virsh net-start <nom_du_réseau>
> ```

---

### 3. Exemple — réseau personnalisé

Configuration pour un réseau `192.168.10.0/24` sur le bridge `br0` :

```elixir
# Dans load_config/0
%{
  server_ip:   ip("192.168.10.1"),
  pool_start:  ip("192.168.10.50"),
  pool_end:    ip("192.168.10.150"),
  subnet_mask: ip("255.255.255.0"),
  router:      ip("192.168.10.1"),
  dns_servers: [ip("192.168.10.1"), ip("1.1.1.1")],
  domain:      "lan.local",
  lease_time:  43_200,  # 12h
  reservations: %{
    "de:ad:be:ef:00:01" => ip("192.168.10.10"),  # NAS
    "de:ad:be:ef:00:02" => ip("192.168.10.11"),  # Imprimante
  }
}

# Dans start/2
{DhcpServer.Socket, [port: 67, bind_ip: {0, 0, 0, 0}, interface: "br0"]},
{DhcpServer.Dns, [
  port: 53,
  bind_ip: {192, 168, 10, 1},
  domain: config.domain,
  interface: "br0",
  upstream: {{1, 1, 1, 1}, 53}
]},
```

---

## Démarrage

> ⚠️ Les ports 67 (DHCP) et 53 (DNS) nécessitent les droits root.

```bash
# Démarrage standard
sudo mix run --no-halt

# Démarrage avec console interactive (recommandé)
sudo iex -S mix
```

---

## Administration en direct (IEx)

```elixir
# Afficher le tableau des baux actifs
DhcpServer.status()

# Lister tous les baux (actifs, expirés, libérés)
DhcpServer.leases()

# Ajouter une réservation statique à chaud (sans redémarrer)
DhcpServer.reserve("de:ad:be:ef:00:01", "192.168.1.60")

# Libérer manuellement le bail d'un client
DhcpServer.release("de:ad:be:ef:00:01")
```

---

## Logs en temps réel

```
╔══════════════════════════════════════════════════════════════════╗
║              DHCP SERVER — Elixir Implementation                 ║
╠══════════════════════════════════════════════════════════════════╣
║  Server IP   : 192.168.1.1                                       ║
║  Pool        : 192.168.1.100 → 192.168.1.200 (101 addrs)        ║
║  DNS domain  : home.local                                        ║
║  Lease time  : 24h (86400s)                                      ║
╚══════════════════════════════════════════════════════════════════╝

🔌 UDP socket open on port 67 (bind: 0.0.0.0 dev=virbr2)
🌐 DNS server listening on 192.168.1.1:53 — domain: .home.local
   Upstream resolver: 8.8.8.8:53

🔍 DHCPDISCOVER from 52:54:00:ed:85:6d (debian) [xid=0x515D4641]
📤 OFFER: 192.168.1.100 → 52:54:00:ed:85:6d (debian)
📋 DHCPREQUEST from 52:54:00:ed:85:6d (debian) [xid=0x515D4641]
✅ ACK: 192.168.1.100 → 52:54:00:ed:85:6d (debian) [lease=24h0m]

🔎 DNS query [192.168.1.100] A debian.home.local
✅ DNS A debian.home.local → 192.168.1.100 [ttl=300s]

⏩ DNS forward google.com → 8.8.8.8 [id=42381]

────────────────────────────────────────────────────────────────────
📊 DHCP SERVER STATUS — 2025-01-10 22:50:00
   Pool       : 192.168.1.100 → 192.168.1.200 (101 addresses)
   Used/Free  : 1/100 (0.99% utilization)
   IP ADDRESS       MAC ADDRESS        EXPIRES IN   HOSTNAME
   192.168.1.100    52:54:00:ed:85:6d  23h 58m      debian
────────────────────────────────────────────────────────────────────
```

---

## Structure des fichiers

```
dhcp_server/
├── mix.exs
├── config/
│   └── config.exs                    # Niveau de log (debug/info)
└── lib/
    ├── dhcp_server.ex                 # API publique (status, reserve, release)
    └── dhcp_server/
        ├── application.ex             # ⚙️  Configuration principale + Supervisor OTP
        ├── packet.ex                  # Parser/builder binaire RFC 2131
        ├── lease_manager.ex           # Pool IP + cycle de vie des baux
        ├── handler.ex                 # Machine à états DHCP (DORA)
        ├── socket.ex                  # Socket UDP port 67
        ├── dns.ex                     # Serveur DNS port 53 + forward upstream
        └── status_reporter.ex         # Logs périodiques du tableau des baux
```
