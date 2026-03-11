import Config

config :logger, :console,
  format: "$time [$level] $message\n",
  metadata: [],
  level: :debug

config :logger,
  level: :debug
