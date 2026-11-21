<!-- Generated from the code by tests/gen_reference.py: do not edit. Run `python3 tests/gen_reference.py` after a change. -->
# Labels

Labels are how a service tells om what it needs. They go in the service's `compose.yml`, under `labels:`, as a list (`- "om.log=off"`) or a map (`om.log: off`). `om add` writes the first table and offers every label in the second as a commented menu, so you uncomment what you need and run `om start`. `om edit` changes the dashboard ones for you.

## Set by `om add`

| Label | Example | What it does |
| :--- | :--- | :--- |
| `workspace.id` | `my-workspace` | the workspace the service belongs to; keeps names unique across workspaces |
| `dashboard.name` | `Web` | the card's title on the dashboard |
| `dashboard.icon` | `🌐` | the card's icon |
| `dashboard.description` | `A small web server` | the card's description |
| `dashboard.port` | `8080` | the container port om routes to |
| `dashboard.domain` | `web.my-workspace.localhost` | the address shown for the service (informational) |
| `dashboard.scope` | `private` | `private` (this machine and your VPN) or `public` (the LAN too) |
| `dashboard.web` | `true` | `false` for a background service with no web address |

## Routing

| Label | Example | What it does |
| :--- | :--- | :--- |
| `om.route.aliases` | `/a,/b` | redirect these top-level paths on the dashboard's address to this service |
| `om.route.keep_prefix` | `true` | the app serves itself under /<service>/ |
| `om.route.dashboard_paths` | `/api/x*` | paths on this service's address answered by the dashboard |
| `om.tcp` | `5432` | publish this container port as a raw TCP route |
| `om.tcp.port` | `15432` | the host port for om.tcp (default: a free slot) |

## Who can reach it

| Label | Example | What it does |
| :--- | :--- | :--- |
| `om.net.allow` | `vpn` | only these addresses reach its own ports (vpn = your VPN allow-list) |
| `om.net.deny` | `203.0.113.0/24` | never these addresses |
| `om.link` | `<ws>/<svc>` | a private network with exactly one other service |
| `om.link.allow` | `<ws>/<svc>` | who may link to this service (both sides must agree) |
| `om.network` | `shared` | join the workspace-wide network instead of this folder's own |

## Outbound traffic

| Label | Example | What it does |
| :--- | :--- | :--- |
| `om.egress` | `audit` | audit \| learn \| internet \| host,*.host: where it may connect out (default: nowhere) |
| `om.egress.learn_ttl` | `24h` | how long learn mode records |
| `om.egress.jvm` | `true` | hand the proxy settings to a JVM service |

## Resources and updates

| Label | Example | What it does |
| :--- | :--- | :--- |
| `om.mem` | `256m` | memory limit |
| `om.pids` | `200` | process limit |
| `om.cpus` | `0.5` | CPU limit |
| `om.update` | `hold` | hold: keep the image's pin; auto: the scheduled sync updates it |

## Logging and policy

| Label | Example | What it does |
| :--- | :--- | :--- |
| `om.log` | `off` | leave no trace: no access or connection log, no output kept |
| `om.policy.allow` | `mounts` | waive these deploy-gate rules for this service (om policy check) |

## Dashboard

| Label | Example | What it does |
| :--- | :--- | :--- |
| `dashboard.hide` | `true` | keep it off the dashboard |
| `dashboard.path` | `/x/` | where the dashboard link opens on the service's address |
| `dashboard.url` | `https://example.org/` | open this address instead of the service's own port |
| `dashboard.search` | `true` | the service is the browser's search engine |
| `dashboard.search_url` | `/search?q={searchTerms}` | its search address |
| `workspace.category` | `tools` | reported by /api/services |
