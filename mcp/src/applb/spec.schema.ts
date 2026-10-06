/**
 * The deployment spec, as advertised to a client. GENERATED — DO NOT EDIT.
 *
 * Produced by `scripts/prune-schema.mjs` from app-lb's
 * `schema/deployment-spec.json`, which app-lb generates from the Rust types
 * themselves. Nothing here was transcribed by hand, which is the point: the
 * three mirrors that were transcribed all drifted, and two of them are wrong
 * today.
 *
 * Descriptions are trimmed to their opening paragraph and a few blocks are
 * collapsed to keep `tools/list` affordable. The full schema for any block is
 * one `applb_spec_schema` call away.
 *
 * Regenerate: `npm run schema` (with app-lb checked out alongside).
 */

export const DEPLOYMENT_SPEC_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "DeploymentSpec",
  "type": "object",
  "properties": {
    "account_id": {
      "description": "The heyo account that pays for this deployment's VMs, and the user who registered it.",
      "type": [
        "string",
        "null"
      ]
    },
    "artifact": {
      "description": "Where `vm.image` is pulled from: a rootfs already in an artifact store.",
      "anyOf": [
        {
          "$ref": "#/$defs/ArtifactSpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "auth": {
      "description": "An optional sign-in gate in front of everything this deployment serves.",
      "anyOf": [
        {
          "$ref": "#/$defs/AuthGate"
        },
        {
          "type": "null"
        }
      ]
    },
    "build": {
      "description": "Where `vm.image` is built from: a git repo and a Dockerfile.",
      "anyOf": [
        {
          "$ref": "#/$defs/BuildSpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "discovery": {
      "description": "Orchestrator service whose healthy endpoint set supplies this static deployment's upstream membership.",
      "anyOf": [
        {
          "$ref": "#/$defs/DiscoverySpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "feed": {
      "description": "Opt-in hooks into the namespace's event feed.",
      "anyOf": [
        {
          "$ref": "#/$defs/FeedSpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "gateway": {
      "description": "Opt-in one-hop regional gateway transport over explicit static upstreams.",
      "anyOf": [
        {
          "$ref": "#/$defs/GatewaySpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "health": {
      "description": "How app-lb decides a replica is ready to take traffic.",
      "$ref": "#/$defs/HealthCheck",
      "default": {
        "path": "/",
        "timeout_secs": 2
      }
    },
    "id": {
      "description": "Unique name for this deployment, and its handle in every other call.",
      "type": "string"
    },
    "ingress": {
      "description": "A second way in, beside `routes`: a URL on the Heyo cloud's domain that reaches the pool through the daemon rather than through this proxy.",
      "anyOf": [
        {
          "$ref": "#/$defs/IngressSpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "maintenance": {
      "description": "Temporarily fence this deployment's public data plane.",
      "type": "boolean"
    },
    "namespace": {
      "description": "The namespace this deployment belongs to.",
      "type": "string"
    },
    "routes": {
      "description": "Which requests reach this deployment, most specific rule winning.",
      "type": "array",
      "items": {
        "$ref": "#/$defs/RouteRule"
      }
    },
    "scaling": {
      "description": "How many replicas run and when.",
      "$ref": "#/$defs/ScalingPolicy",
      "default": {
        "boot_timeout_secs": 300,
        "cold_start_timeout_secs": 120,
        "drain_timeout_secs": 30,
        "idle_action": "destroy",
        "max_replicas": 5,
        "min_replicas": 0,
        "scale_to_zero_after_secs": 300,
        "target_concurrency": 10,
        "warm_pool": 0
      }
    },
    "site": {
      "description": "Serve files from a directory on this host, with no backend at all — the third kind of deployment, alongside a managed VM pool and a `proxy_pass` upstream list.",
      "anyOf": [
        {
          "$ref": "#/$defs/SiteSpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "update": {
      "description": "How a *static* deployment's backend is updated: a working directory on this host and commands to run in it.",
      "anyOf": [
        {
          "$ref": "#/$defs/UpdateSpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "upstreams": {
      "description": "A *static* (proxy_pass) deployment: forward matched requests to a fixed set of upstream addresses (`host:port` or `ip:port`) with no VM lifecycle and no autoscaling.",
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "user_id": {
      "type": [
        "string",
        "null"
      ]
    },
    "vm": {
      "description": "The VM template for a *managed* deployment: app-lb boots and autoscales a pool of microVMs.",
      "anyOf": [
        {
          "$ref": "#/$defs/VmSpec"
        },
        {
          "type": "null"
        }
      ]
    }
  },
  "required": [
    "id",
    "routes"
  ],
  "$defs": {
    "ArtifactSpec": {
      "description": "Where a deployment's content comes from: bytes already in an artifact store, addressed by content.",
      "type": "object",
      "properties": {
        "auth": {
          "description": "API key for a store started with `ART_API_KEY`, as a reference into the secret store.",
          "anyOf": [
            {
              "$ref": "#/$defs/SecretRef"
            },
            {
              "type": "null"
            }
          ]
        },
        "grow_gb": {
          "description": "Extend the materialized rootfs to this many gigabytes.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint64",
          "minimum": 0
        },
        "image_name": {
          "description": "Base name for the materialized image; the digest is appended, so one deployment's pulls are `<name>-<short digest>`.",
          "type": [
            "string",
            "null"
          ]
        },
        "ref": {
          "description": "A tag (`debian-hermes`, `marketing-live`) or a 64-hex digest.",
          "type": "string"
        },
        "store": {
          "description": "The store to pull from, in one of two forms:",
          "type": "string"
        },
        "strip_components": {
          "description": "Leading path components to drop from every entry while unpacking, exactly as `tar --strip-components` does.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint",
          "minimum": 0
        }
      },
      "required": [
        "store",
        "ref"
      ]
    },
    "AuthGate": {
      "type": "object",
      "additionalProperties": true,
      "description": "An optional sign-in gate in front of a deployment. (Call applb_spec_schema with block \"AuthGate\" for the full shape; everything it accepted is still accepted.)"
    },
    "BuildSpec": {
      "description": "Where a deployment's guest image is *built* from — a Dockerfile, and the files it copies in.",
      "type": "object",
      "properties": {
        "auth": {
          "description": "Credential, as a reference into the secret store.",
          "anyOf": [
            {
              "$ref": "#/$defs/SecretRef"
            },
            {
              "type": "null"
            }
          ]
        },
        "context": {
          "description": "Build context within the checkout.",
          "type": [
            "string",
            "null"
          ]
        },
        "dockerfile": {
          "description": "Dockerfile path *within the checkout*.",
          "type": [
            "string",
            "null"
          ]
        },
        "image_name": {
          "description": "Base name for built images; the source version is appended, so one deployment's builds are `<name>-<short sha>` from git and `<name>-<short manifest digest>` from a store.",
          "type": [
            "string",
            "null"
          ]
        },
        "image_size_mb": {
          "description": "Rootfs size passed to `heyvm mvm build --size-mb`.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint64",
          "minimum": 0
        },
        "ref": {
          "description": "Which version of the source to build.",
          "type": [
            "string",
            "null"
          ]
        },
        "repo": {
          "description": "Git remote: `https://…`, `ssh://…`, `git@host:path`, or a local path.",
          "type": [
            "string",
            "null"
          ]
        },
        "store": {
          "description": "An artifact store holding a Dockerfile manifest: an `http(s)://` URL of an `art serve`, or an absolute store root on this host.",
          "type": [
            "string",
            "null"
          ]
        }
      }
    },
    "DiscoverySpec": {
      "type": "object",
      "additionalProperties": true,
      "description": "DiscoverySpec (Call applb_spec_schema with block \"DiscoverySpec\" for the full shape; everything it accepted is still accepted.)"
    },
    "Driver": {
      "description": "Which runtime boots a deployment's replicas.",
      "oneOf": [
        {
          "type": "string",
          "enum": [
            "firecracker",
            "kvm",
            "libvirt",
            "firecracker_containerd"
          ]
        },
        {
          "description": "A system container under Incus, booted from an OCI image.",
          "type": "string",
          "const": "lxc"
        }
      ]
    },
    "ExpectedHeader": {
      "type": "object",
      "additionalProperties": true,
      "description": "A response identity assertion, in addition to HTTP success. (Call applb_spec_schema with block \"ExpectedHeader\" for the full shape; everything it accepted is still accepted.)"
    },
    "FeedSpec": {
      "type": "object",
      "additionalProperties": true,
      "description": "A deployment's opt-in hooks into its namespace's event feed. (Call applb_spec_schema with block \"FeedSpec\" for the full shape; everything it accepted is still accepted.)"
    },
    "GatewaySpec": {
      "type": "object",
      "additionalProperties": true,
      "description": "GatewaySpec (Call applb_spec_schema with block \"GatewaySpec\" for the full shape; everything it accepted is still accepted.)"
    },
    "HealthCheck": {
      "description": "How a freshly-booted VM is proven ready before it joins the pool.",
      "type": "object",
      "properties": {
        "expected_header": {
          "description": "With an identity assertion, require a 2xx response and exactly one matching header.",
          "anyOf": [
            {
              "$ref": "#/$defs/ExpectedHeader"
            },
            {
              "type": "null"
            }
          ]
        },
        "path": {
          "description": "`None` means a bare TCP connect is enough.",
          "type": [
            "string",
            "null"
          ],
          "default": "/"
        },
        "port": {
          "description": "Health port, if the guest serves health somewhere other than `port`.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint16",
          "maximum": 65535,
          "minimum": 0
        },
        "timeout_secs": {
          "description": "How long a single probe may take before it counts as a failure.",
          "type": "integer",
          "format": "uint64",
          "default": 2,
          "minimum": 0
        }
      }
    },
    "IdleAction": {
      "description": "What becomes of a VM the autoscaler no longer needs.",
      "oneOf": [
        {
          "description": "Kill it: the sandbox, its data disk and its rootfs all go.",
          "type": "string",
          "const": "destroy"
        },
        {
          "description": "Stop it: the sandbox stays, keeping its data disk, and a later request or `exec` resumes it instead of booting a fresh one.",
          "type": "string",
          "const": "retain"
        }
      ]
    },
    "IngressSpec": {
      "type": "object",
      "additionalProperties": true,
      "description": "How a managed deployment is reached from the Heyo cloud. (Call applb_spec_schema with block \"IngressSpec\" for the full shape; everything it accepted is still accepted.)"
    },
    "RouteRule": {
      "description": "How a request is matched to a deployment.",
      "type": "object",
      "properties": {
        "host": {
          "description": "Exact hostname match, case-insensitive, port stripped.",
          "type": [
            "string",
            "null"
          ]
        },
        "host_suffix": {
          "description": "Subdomain (wildcard) host match: a domain whose apex *and* any subdomain match — `host_suffix: \"apps.example.com\"` routes `apps.example.com`, `a.apps.example.com`, and `x.y.apps.ex…",
          "type": [
            "string",
            "null"
          ]
        },
        "path_prefix": {
          "description": "Path prefix match, e.g.",
          "type": [
            "string",
            "null"
          ]
        },
        "strip_prefix": {
          "description": "Remove `path_prefix` before forwarding to the upstream.",
          "type": "boolean"
        }
      }
    },
    "SandboxSize": {
      "description": "`heyo_sdk::SandboxSize`, mirrored for schema generation only.",
      "type": "string",
      "enum": [
        "micro",
        "mini",
        "small",
        "medium",
        "large",
        "xlarge"
      ]
    },
    "ScalingPolicy": {
      "type": "object",
      "properties": {
        "boot_timeout_secs": {
          "description": "How long a booting VM has to pass its health check before the autoscaler gives up on it, kills it and lets the next tick create a replacement.",
          "type": "integer",
          "format": "uint64",
          "default": 300,
          "minimum": 0
        },
        "cold_start_timeout_secs": {
          "description": "How long a request will wait for a VM to boot before giving up with 503.",
          "type": "integer",
          "format": "uint64",
          "default": 120,
          "minimum": 0
        },
        "drain_timeout_secs": {
          "description": "How long a draining VM may keep serving in-flight requests before it is killed anyway.",
          "type": "integer",
          "format": "uint64",
          "default": 30,
          "minimum": 0
        },
        "idle_action": {
          "description": "Whether a VM the autoscaler retires is destroyed or merely stopped.",
          "$ref": "#/$defs/IdleAction",
          "default": "destroy"
        },
        "max_replicas": {
          "description": "Ceiling on replicas the autoscaler may run.",
          "type": "integer",
          "format": "uint32",
          "default": 5,
          "minimum": 0
        },
        "min_replicas": {
          "description": "Replicas kept running even with no traffic.",
          "type": "integer",
          "format": "uint32",
          "default": 0,
          "minimum": 0
        },
        "scale_to_zero_after_secs": {
          "description": "Idle seconds before a pool with `min_replicas: 0` and no warm pool is torn down entirely.",
          "type": "integer",
          "format": "uint64",
          "default": 300,
          "minimum": 0
        },
        "target_concurrency": {
          "description": "In-flight requests per VM the autoscaler aims for.",
          "type": "integer",
          "format": "uint32",
          "default": 10,
          "minimum": 0
        },
        "warm_pool": {
          "description": "Idle-but-ready spares kept above what current load requires.",
          "type": "integer",
          "format": "uint32",
          "default": 0,
          "minimum": 0
        }
      }
    },
    "SecretRef": {
      "description": "A pointer to one value inside one secret, as a deployment spec spells it.",
      "type": "object",
      "properties": {
        "key": {
          "description": "Which key inside it.",
          "type": "string",
          "default": "token"
        },
        "namespace": {
          "description": "The namespace the secret lives in.",
          "type": [
            "string",
            "null"
          ]
        },
        "secret": {
          "description": "The secret's id.",
          "type": "string"
        },
        "username": {
          "description": "Username to pair the value with, for the (rare) forge that wants a real one.",
          "type": [
            "string",
            "null"
          ]
        }
      },
      "required": [
        "secret"
      ]
    },
    "SiteSpec": {
      "type": "object",
      "additionalProperties": true,
      "description": "A static *site*: a directory on this host, served straight off disk. (Call applb_spec_schema with block \"SiteSpec\" for the full shape; everything it accepted is still accepted.)"
    },
    "UpdateSpec": {
      "type": "object",
      "additionalProperties": true,
      "description": "How a *static* (proxy_pass) deployment's backend is updated: a working directory on the app-lb host, and commands to run in it. (Call applb_spec_schema with block \"UpdateSpec\" for the full shape; everything it accepted is still accepted.)"
    },
    "VmSpec": {
      "description": "The VM template. (10 more fields — correlated_creates, env_from, image_download_url, image_sha256, image_size_bytes, mounts, rootfs, setup_hooks, workspace, workspace_archive — omitted here for size. Call applb_spec_schema with block \"VmSpec\" for the full shape; everything it accepted is still accepted.)",
      "type": "object",
      "properties": {
        "disk_size_gb": {
          "description": "Size of the replica's persistent data disk, mounted at `/workspace`.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint32",
          "minimum": 0
        },
        "driver": {
          "description": "`firecracker` or `kvm` (a heyvm microVM) or `lxc` (an Incus system container from an OCI image).",
          "$ref": "#/$defs/Driver"
        },
        "env_vars": {
          "description": "Plain environment variables for every replica.",
          "type": [
            "object",
            "null"
          ],
          "additionalProperties": {
            "type": "string"
          }
        },
        "image": {
          "description": "Defaults to `ubuntu:24.04` daemon-side when unset.",
          "type": [
            "string",
            "null"
          ]
        },
        "open_ports": {
          "description": "Guest ports to open *in addition to* [`port`](Self::port), which is added automatically.",
          "type": "array",
          "items": {
            "type": "integer",
            "format": "uint16",
            "maximum": 65535,
            "minimum": 0
          }
        },
        "port": {
          "description": "The guest port traffic is proxied to.",
          "type": "integer",
          "format": "uint16",
          "maximum": 65535,
          "minimum": 0
        },
        "size_class": {
          "description": "CPU and memory, as one of the daemon's named classes.",
          "anyOf": [
            {
              "$ref": "#/$defs/SandboxSize"
            },
            {
              "type": "null"
            }
          ]
        },
        "start_command": {
          "description": "Shell command that starts the workload, run once per replica after boot.",
          "type": [
            "string",
            "null"
          ]
        },
        "ttl_seconds": {
          "description": "Backstop TTL so VMs die on their own if this LB crashes and never reaps them.",
          "type": "integer",
          "format": "uint64",
          "default": 3600,
          "minimum": 0
        },
        "working_directory": {
          "description": "Directory `start_command` runs in.",
          "type": [
            "string",
            "null"
          ]
        }
      },
      "required": [
        "driver",
        "port"
      ],
      "additionalProperties": true
    }
  }
};

/**
 * The same schema with nothing removed: every field, every doc comment.
 *
 * Returned by `applb_spec_schema`, never advertised. This is what makes the
 * pruning above a trade rather than a loss — the detail is one call away
 * instead of on every connect.
 */
export const DEPLOYMENT_SPEC_FULL = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "DeploymentSpec",
  "type": "object",
  "properties": {
    "account_id": {
      "description": "The heyo account that pays for this deployment's VMs, and the user who\nregistered it. Stamped by app-lb from the caller's federated grant (the\nnamespace's owning account) on every register and update, overriding\nwhatever the body said; an operator or local-token caller keeps what it\nsent, which on a self-hosted app-lb is usually nothing. Passed to the\ndaemon on every VM create so the sandbox is metered to the right\naccount — including the replacements the autoscaler boots with no\ncaller present.",
      "type": [
        "string",
        "null"
      ]
    },
    "artifact": {
      "description": "Where `vm.image` is pulled from: a rootfs already in an artifact store.\nThe alternative to `build` and mutually exclusive with it — both rewrite\n`vm.image`, and a deployment with two sources for it would have no\nanswer to \"where did this image come from\".\n\nLike `build`, editing it disturbs nothing; the pool moves when a pull\nfinishes.",
      "anyOf": [
        {
          "$ref": "#/$defs/ArtifactSpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "auth": {
      "description": "An optional sign-in gate in front of everything this deployment serves.\nApplies to either backend kind — it runs in the proxy, before a backend\nis chosen — so the application behind it needs to know nothing about it.",
      "anyOf": [
        {
          "$ref": "#/$defs/AuthGate"
        },
        {
          "type": "null"
        }
      ]
    },
    "build": {
      "description": "Where `vm.image` is built from: a git repo and a Dockerfile. Optional —\na deployment can go on naming a prebuilt image — and only valid on a\nmanaged deployment, since a static one has no image to build.\n\nNot part of `VmSpec`, so editing it is not a template change and does not\nrecycle the pool. The pool moves when a build finishes and rewrites\n`vm.image`.",
      "anyOf": [
        {
          "$ref": "#/$defs/BuildSpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "discovery": {
      "description": "Orchestrator service whose healthy endpoint set supplies this static\ndeployment's upstream membership.",
      "anyOf": [
        {
          "$ref": "#/$defs/DiscoverySpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "feed": {
      "description": "Opt-in hooks into the namespace's event feed. Absent means this\ndeployment publishes nothing and exposes nothing — the feed only ever\ncarries what a spec explicitly asked it to. See [`FeedSpec`].",
      "anyOf": [
        {
          "$ref": "#/$defs/FeedSpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "gateway": {
      "description": "Opt-in one-hop regional gateway transport over explicit static upstreams.",
      "anyOf": [
        {
          "$ref": "#/$defs/GatewaySpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "health": {
      "description": "How app-lb decides a replica is ready to take traffic. Defaults to an\nHTTP GET of `/` on the deployment's own port.",
      "$ref": "#/$defs/HealthCheck",
      "default": {
        "path": "/",
        "timeout_secs": 2
      }
    },
    "id": {
      "description": "Unique name for this deployment, and its handle in every other call.\nRegistering an id that already exists REPLACES that deployment.",
      "type": "string"
    },
    "ingress": {
      "description": "A second way in, beside `routes`: a URL on the Heyo cloud's domain\nthat reaches the pool through the daemon rather than through this\nproxy. See [`IngressSpec`]. Managed deployments only.",
      "anyOf": [
        {
          "$ref": "#/$defs/IngressSpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "maintenance": {
      "description": "Temporarily fence this deployment's public data plane. Routed requests\nreceive HTTP 503 before auth or backend selection, while deployment\nmanagement and VM exec remain available on the separate admin listener.\nPersisted as part of the deployment spec and safe to toggle with PUT.",
      "type": "boolean"
    },
    "namespace": {
      "description": "The namespace this deployment belongs to. Namespaces segregate use: a\ntoken minted for a namespace reaches only the deployments in it, and the\nevent feed is kept per namespace. Absent means `\"default\"`, so a fleet\nthat never says the word keeps behaving as one namespace.",
      "type": "string"
    },
    "routes": {
      "description": "Which requests reach this deployment, most specific rule winning.\n\nMay be empty only for a `vm` deployment, which is then reachable by exec\nand shell but takes no HTTP traffic. A static deployment and a site are\nreachable only through the proxy, so both need at least one.",
      "type": "array",
      "items": {
        "$ref": "#/$defs/RouteRule"
      }
    },
    "scaling": {
      "description": "How many replicas run and when. Every field defaults, so the whole block\nmay be omitted; it applies to a `vm` deployment (a static deployment's\nupstreams and a site's files are not app-lb's to scale).",
      "$ref": "#/$defs/ScalingPolicy",
      "default": {
        "boot_timeout_secs": 300,
        "cold_start_timeout_secs": 120,
        "drain_timeout_secs": 30,
        "idle_action": "destroy",
        "max_replicas": 5,
        "min_replicas": 0,
        "scale_to_zero_after_secs": 300,
        "target_concurrency": 10,
        "warm_pool": 0
      }
    },
    "site": {
      "description": "Serve files from a directory on this host, with no backend at all — the\nthird kind of deployment, alongside a managed VM pool and a `proxy_pass`\nupstream list. See [`SiteSpec`].",
      "anyOf": [
        {
          "$ref": "#/$defs/SiteSpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "update": {
      "description": "How a *static* deployment's backend is updated: a working directory on\nthis host and commands to run in it. The static counterpart of `build`,\nand mutually exclusive with it for the same reason the backend kinds are.",
      "anyOf": [
        {
          "$ref": "#/$defs/UpdateSpec"
        },
        {
          "type": "null"
        }
      ]
    },
    "upstreams": {
      "description": "A *static* (proxy_pass) deployment: forward matched requests to a fixed\nset of upstream addresses (`host:port` or `ip:port`) with no VM lifecycle\nand no autoscaling. Load-balanced least-in-flight with failover, and\nhealth-re-probed by the autoscaler so a recovered upstream rejoins.\nMutually exclusive with `vm`.",
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "user_id": {
      "type": [
        "string",
        "null"
      ]
    },
    "vm": {
      "description": "The VM template for a *managed* deployment: app-lb boots and autoscales a\npool of microVMs. Mutually exclusive with `upstreams`; exactly one of the\ntwo must be set.",
      "anyOf": [
        {
          "$ref": "#/$defs/VmSpec"
        },
        {
          "type": "null"
        }
      ]
    }
  },
  "required": [
    "id",
    "routes"
  ],
  "$defs": {
    "AdminScope": {
      "description": "What a token may do on the admin API.",
      "oneOf": [
        {
          "description": "No admin API access. Still usable against a deployment's data-plane gate,\nwhich is the whole point of a token handed to an application.",
          "type": "string",
          "const": "none"
        },
        {
          "description": "`/metrics` and `/dashboard`.",
          "type": "string",
          "const": "view"
        },
        {
          "description": "Everything, within the token's `deployments` scope.",
          "type": "string",
          "const": "admin"
        }
      ]
    },
    "ArtifactSpec": {
      "description": "Where a deployment's content comes from: bytes already in an artifact store,\naddressed by content.\n\nTwo backends read this block, and what the same digest means differs:\n\n* A **managed (`vm`) deployment** pulls a *guest rootfs*. The blob is\n  materialized as an ext4 file heyvmd can boot and [`VmSpec::image`] is\n  rewritten to it, so the spec still says which image is actually booting and\n  this block says where the next one comes from.\n* A **site** pulls a *directory tree* — a `tar` or `tar.gz` of built files,\n  unpacked into [`SiteSpec::root`]. This is the counterpart of\n  [`UpdateSpec`] and the reason to prefer it: the host needs no toolchain at\n  all, because the build already happened wherever the bundle was made.\n\nThe counterpart of [`BuildSpec`], and the same shape of thing: the *source*\nof the next content, not the running one.\n\nWhat makes this different from a build is that nothing is *produced*. The\ndigest names bytes that already exist, so the same `artifact` block resolves\nto the same content on every host that can reach the store, which is the\nwhole reason to prefer it over rebuilding per machine. It is also what makes\na rollback expressible: a tag moves, a digest cannot.\n\nSee <https://github.com/sarocu/artifacts> — `art heyvm import` puts heyvm's\nbase images in, `art put dist.tgz --tag <name>` puts a site bundle in,\n`heyctl artifact push` puts a locally-built rootfs in, and any of them is\npullable here.",
      "type": "object",
      "properties": {
        "auth": {
          "description": "API key for a store started with `ART_API_KEY`, as a reference into the\nsecret store. Only meaningful for the URL form — a local store is\nprotected by file permissions, not a header.",
          "anyOf": [
            {
              "$ref": "#/$defs/SecretRef"
            },
            {
              "type": "null"
            }
          ]
        },
        "grow_gb": {
          "description": "Extend the materialized rootfs to this many gigabytes. Sparse, so it\ncosts no disk until the guest writes; heyvm still runs the `resize2fs`\nthat lets the guest filesystem use the room. Set it when the image was\nbuilt small and the workload needs space on `/`.\n\nGuest images only — a site has no filesystem to grow.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint64",
          "minimum": 0
        },
        "image_name": {
          "description": "Base name for the materialized image; the digest is appended, so one\ndeployment's pulls are `<name>-<short digest>`. Defaults to the\ndeployment id.\n\nGuest images only — a site's files land in `site.root` under their own\nnames.",
          "type": [
            "string",
            "null"
          ]
        },
        "ref": {
          "description": "A tag (`debian-hermes`, `marketing-live`) or a 64-hex digest. A tag is\nresolved at pull time, so a deployment pinned to one follows whatever the\ntag moves to; a digest is immutable and is what a rollback should name.",
          "type": "string"
        },
        "store": {
          "description": "The store to pull from, in one of two forms:\n\n* `http://host:port` — a remote `art serve`. app-lb resolves and streams\n  the blob itself, verifying the digest as the bytes land.\n* `/abs/path` — a store root (`ART_ROOT`) on this host. app-lb shells out\n  to the `art` CLI: `art heyvm materialize` for a rootfs, which skips the\n  blob's holes instead of copying its zeros, and `art get` for a site\n  bundle, which hardlinks it and copies nothing at all.\n\nA local store is by far the faster of the two and is what a host running\nits own store should use; the URL form is what makes one store serve a\nfleet.",
          "type": "string"
        },
        "strip_components": {
          "description": "Leading path components to drop from every entry while unpacking, exactly\nas `tar --strip-components` does.\n\nSites only, and it exists because of how the bundle was almost certainly\nmade: `tar czf dist.tgz dist` writes every entry as `dist/…`, so\nunpacking it straight into `site.root` puts the index at\n`<root>/dist/index.html` and the deployment 404s everything. `1` drops\nthat wrapper. A bundle rolled with `tar czf dist.tgz -C dist .` needs\nnothing here.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint",
          "minimum": 0
        }
      },
      "required": [
        "store",
        "ref"
      ]
    },
    "AuthGate": {
      "description": "An optional sign-in gate in front of a deployment.\n\nOrthogonal to the backend kind on purpose: a managed VM pool and a static\n`proxy_pass` target are gated identically, because this happens in the proxy\nbefore either is reached. The application behind it needs to know nothing\nabout OAuth — it sees only requests that got past the gate, optionally with\nthe caller's identity in headers.\n\nThe client *secret* is a [`SecretRef`], not a value, for the same reason a\nbuild's git token is: the admin API echoes specs back and the state file\nholds them in the clear.",
      "type": "object",
      "properties": {
        "allowed_domains": {
          "description": "Google Workspace domains whose accounts may enter, matched against the\n`hd` claim (not the email's suffix — see `AuthGate::allows`). `[\"*\"]`\nmeans *any* Google account, which is a real choice and has to be spelled\nout.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "allowed_emails": {
          "description": "Individual addresses allowed regardless of domain.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "base_path": {
          "description": "Where app-lb's own endpoints live under this deployment's hostname:\n`<base_path>/callback`, `/login` and `/logout`. The callback is the URL\nthat must be registered with the provider.",
          "type": "string",
          "default": "/__applb/auth"
        },
        "client_id": {
          "description": "OAuth client id from the provider's console. Required for `google`,\nmeaningless without it.",
          "type": [
            "string",
            "null"
          ]
        },
        "client_secret": {
          "description": "Where the client secret is stored. Required for `google`.",
          "anyOf": [
            {
              "$ref": "#/$defs/SecretRef"
            },
            {
              "type": "null"
            }
          ]
        },
        "cookie_domain": {
          "description": "Widen the session cookie to a parent domain, so one sign-in covers every\ndeployment under it. Unset means host-only: the default, and the safe one.\n\nThis is the answer to \"why does opening each service from the directory\nsend me back to Google?\". Cookies are scoped to the host that set them, so\nsigning in at `docs.example.com` leaves `api.example.com` with nothing to\npresent. Setting `\"cookie_domain\": \"example.com\"` on both gates makes the\nsession one realm, and the second service admits the browser without a\nround trip.\n\nTwo properties make that safe, and both are load-bearing:\n\n* **The cookie is only wider; the check is not.** A session is still\n  refused unless the gate presenting it has a byte-identical\n  [`AuthGate::policy_fingerprint`], which covers the provider, client id,\n  allowed domains, allowed emails *and* this field. Two gates share a\n  session only when either would have admitted the same person anyway.\n* **It is opt-in.** A cookie scoped to `example.com` is sent to every\n  host under it, including ones app-lb does not serve. If anything else\n  on that domain is untrusted — a customer subdomain, a legacy box — this\n  hands it your session cookie. `HttpOnly` keeps scripts off it, nothing\n  keeps a server on that domain off it.\n\nMust be the request host or a parent of it, at a label boundary. A value\nthe browser would reject is refused at registration, because the failure\nit produces — the cookie silently dropped, sign-in looping forever — is\nalmost impossible to diagnose from the outside.",
          "type": [
            "string",
            "null"
          ]
        },
        "cookie_name": {
          "description": "The session cookie's name. Worth changing only if it collides with one\nthe application already sets.",
          "type": "string",
          "default": "applb_session"
        },
        "forward_identity": {
          "description": "Pass the identity upstream as `x-auth-request-{email,user,name}`\n(oauth2-proxy's spelling, so apps that already read those work unchanged).\nThose headers are stripped from the incoming request either way, so a\nclient cannot forge them.",
          "type": "boolean",
          "default": true
        },
        "jwt": {
          "description": "How to verify a JWT, when `jwt` is among the providers. See [`JwtSpec`].",
          "anyOf": [
            {
              "$ref": "#/$defs/JwtSpec"
            },
            {
              "type": "null"
            }
          ]
        },
        "provider": {
          "description": "Which credentials get past the gate. A bare string for one\n(`\"provider\": \"google\"`) or a list for several\n(`\"provider\": [\"google\", \"app-token\"]`) — see [`Providers`].\n\nMore than one is the common shape rather than an exotic one: a sandbox\nhosting a UI wants a person to sign in with Google *and* the agent\ndriving it to present an app-token. Any one of the listed providers\nadmits a request; they are alternatives, not requirements.",
          "$ref": "#/$defs/Providers",
          "default": "google"
        },
        "provider_ref": {
          "description": "Inherit the *identity* half of this gate from a named provider declared on\nthe deployment's namespace. See [`AuthProviderSpec`].\n\nWhen set, this gate carries only the route-scoped fields — `public_paths`,\n`session_scope`, `base_path`, `cookie_name`, `redirect_url`,\n`forward_identity`, `session_ttl_secs` — and the provider supplies who may\nenter and how they are verified (`provider`, `client_id`, `client_secret`,\n`allowed_domains`, `allowed_emails`, `jwt`, `cookie_domain`). Setting any\nof those inline *and* a reference is refused\n([`SpecError::ProviderRefWithInlineIdentity`]) rather than silently\noverridden, because whoever wrote them believes they take effect.\n\nResolution is live: app-lb looks the provider up on every gated request,\nso rotating the client secret or tightening the allow-list on the provider\npropagates to every deployment that names it — and, because the resolved\ngate's [`policy_fingerprint`](Self::policy_fingerprint) changes with it,\nre-signs the sessions issued under the old policy. A reference that names\nno provider in the namespace is refused at registration, and if one is\nremoved out from under a live deployment the gate fails *closed*.",
          "type": [
            "string",
            "null"
          ]
        },
        "public_paths": {
          "description": "Path prefixes the *sign-in* gate does not sit in front of.\n\nThis list was never \"paths with no authorization\" — it is \"paths an API\nclient reaches without being sent to Google\", which is a different\nthing and was too easily read as the first. Each entry now carries the\nscope app-lb requires in the gate's place, and an entry written as a\nbare string means [`PathScope::Admin`]: the fail-closed reading, because\nthe alternative default is the one that leaked.\n\nA path whose *upstream* does its own authorization — an artifact store\nchecking its API key, a secret service checking a bearer — says so with\n`{\"path\": \"/blobs/\", \"scope\": \"public\"}`. That is the only spelling that\nmeans \"no credential at all\", and it has to be written out.",
          "type": "array",
          "items": {
            "$ref": "#/$defs/PublicPath"
          }
        },
        "redirect_url": {
          "description": "Redirect URI to send the provider, when app-lb cannot derive it from the\nrequest — something in front rewriting the host or terminating TLS\nelsewhere. Normally unset: `https://<request host><base_path>/callback`.",
          "type": [
            "string",
            "null"
          ]
        },
        "session_scope": {
          "description": "Mint an app-token when somebody signs in here, and present it upstream\nfor the life of their session.\n\nThis exists because a sign-in gate and the thing behind it are two\ndifferent checks. A browser that has signed in with Google holds a\nsession cookie, which the *upstream* has no way to verify — so a\ndeployment fronting an API that authenticates for itself (app-lb's own\nadmin listener, most of all) had no way to accept a signed-in person\nexcept by turning its own authentication off. That is how a dashboard\nends up served by an unauthenticated CRUD API.\n\nWith this set, the gate mints a real app-token at the callback, scoped\nas named here and expiring with the session, and the proxy presents it\nas `Authorization: Bearer` on every request that session admits. The\nupstream then authenticates the person the same way it authenticates any\nother client, and scope-checks them the same way too.\n\n**Absent means no token is minted**, which is the right default for\nevery gate in front of an ordinary application: signing in to a web app\nshould not hand the browser a credential for app-lb's admin API. Set it\nonly on a deployment whose upstream you mean to authorize this way.",
          "anyOf": [
            {
              "$ref": "#/$defs/AdminScope"
            },
            {
              "type": "null"
            }
          ]
        },
        "session_ttl_secs": {
          "description": "How long a session lasts before the user is sent back to the provider.",
          "type": "integer",
          "format": "uint64",
          "default": 43200,
          "minimum": 0
        }
      }
    },
    "AuthProvider": {
      "oneOf": [
        {
          "description": "Google sign-in: an OAuth redirect, a session cookie, an allow-list of\ndomains and addresses. For people in browsers.",
          "type": "string",
          "const": "google"
        },
        {
          "description": "An app-token app-lb minted, presented as `Authorization: Bearer applb_…`\nor `?app_token=`. For programs — and for a browser WebSocket, which\ncannot set headers at all.\n\nThe allow-list here is the *token's* `deployments` scope, not\n`allowed_domains`/`allowed_emails`: those describe humans and mean\nnothing for a credential issued to a process.",
          "type": "string",
          "const": "app-token"
        },
        {
          "description": "A JWT somebody else issued, presented as `Authorization: Bearer <jwt>`\nor in a cookie the gate names. For an application whose users already\nsign in somewhere else — the Heyo auth API, or any OIDC provider.\n\nUnlike the other two this gate holds no state at all: there is no session\nto issue and no token table to look in, because the credential carries\nits own proof. Configured by [`AuthGate::jwt`]; the allow-list is that\nblock's `require`, for the reason given there.",
          "type": "string",
          "const": "jwt"
        }
      ]
    },
    "BuildSpec": {
      "description": "Where a deployment's guest image is *built* from — a Dockerfile, and the\nfiles it copies in.\n\nThis is the *source*, not the running image. A build assembles the recipe and\nits context on this host, hands them to `heyvm mvm build`, and only then\nwrites the resulting image name into [`VmSpec::image`] — so the spec always\nsays which image is actually booting, and this block says where the next one\nwill come from. Editing it never disturbs running VMs; running a build does.\n\nOn a **site** it is the files themselves: `repo` at `ref` is checked out and\nits `context` directory (default: the whole checkout, minus `.git`) is copied\ninto `site.root` with the same staged swap an artifact pull uses. Nothing is\nbuilt or run, so `store`, `dockerfile`, `image_name` and `image_size_mb` are\nrefused there. This is how a repo on a Heyo git remote becomes a site.\n\nTwo ways to get the recipe here, and exactly one of them must be set:\n\n* **`repo`** — a git checkout. app-lb fetches `repo` at `ref` and looks for a\n  Dockerfile inside it. The original form, and the right one when the recipe\n  lives with the code it builds.\n* **`store`** — a Dockerfile manifest in an artifact store, named by `ref`.\n  app-lb fetches the manifest, writes out its `Dockerfile` and unpacks its\n  `context.tar.gz`. See [`ArtifactSpec`] for the two spellings of `store`, and\n  `art dockerfile put` in the artifacts crate for how one gets there.\n\nThe difference that matters is *what the ref pins*. A git ref pins a commit,\nand the Dockerfile is whatever that commit happens to hold; a store ref\nresolves to a manifest digest covering the recipe, the context and the\nannotations together. So a store build can say \"these exact inputs\" in a way a\nbranch name cannot, and a rollback is expressible: a tag moves, a digest does\nnot.\n\nIt remains a *build* either way, which is why this is one block and not two.\nBoth run `heyvm mvm build` and produce an image that did not exist before,\nwhich is the whole distinction from [`ArtifactSpec`] — there, the digest names\nbytes that already exist and nothing is produced at all.\n\nNote what is deliberately absent: build arguments and a registry. The image is\nan ext4 rootfs on this host, built from a Dockerfile the daemon never sees, and\n`heyvm mvm build` exposes neither `--build-arg` nor a push target for the\nlocal-only path.",
      "type": "object",
      "properties": {
        "auth": {
          "description": "Credential, as a reference into the secret store. What it *is* depends on\nthe source, which is why it is one field: a git token for a private `repo`,\nor the `ART_API_KEY` of a gated `store`.\n\nUnused by an `ssh://` or `git@` remote, which authenticates with the host's\nown key material, and by a local store root, which is protected by file\npermissions. Both cases are warned about at build time rather than\nrejected here — a spec may legitimately carry one while its `repo` is\nbeing switched.",
          "anyOf": [
            {
              "$ref": "#/$defs/SecretRef"
            },
            {
              "type": "null"
            }
          ]
        },
        "context": {
          "description": "Build context within the checkout. Defaults to the Dockerfile's directory,\nmatching `heyvm mvm build`'s own default. Git source only, for the same\nreason as `dockerfile`.",
          "type": [
            "string",
            "null"
          ]
        },
        "dockerfile": {
          "description": "Dockerfile path *within the checkout*. `None` looks for one: `Dockerfile`\nat the context root, else a unique `Dockerfile` within three directories\nof it. Ambiguity is an error, never a guess.\n\nGit source only: a Dockerfile manifest names its own recipe, so a path\nhere would be pointing into an archive this deployment does not choose the\nlayout of.",
          "type": [
            "string",
            "null"
          ]
        },
        "image_name": {
          "description": "Base name for built images; the source version is appended, so one\ndeployment's builds are `<name>-<short sha>` from git and\n`<name>-<short manifest digest>` from a store. Defaults to the deployment\nid, and overrides the manifest's own `heyvm.image` annotation.",
          "type": [
            "string",
            "null"
          ]
        },
        "image_size_mb": {
          "description": "Rootfs size passed to `heyvm mvm build --size-mb`. Unset lets heyvm size\nit from the exported tar (×1.2 + 64 MB), which is right until the guest\nwrites to its own rootfs at runtime. On a store source, unset falls back\nto the manifest's `heyvm.size_mb` annotation before heyvm's own default.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint64",
          "minimum": 0
        },
        "ref": {
          "description": "Which version of the source to build.\n\nFor a `repo`: a branch, tag or commit. `None` follows the remote's default\nbranch, which is what makes `POST …/build` mean \"ship what is on main\".\n\nFor a `store`: the tag or digest of a Dockerfile manifest, and **required**\n— a store has no default, and guessing one would be picking somebody's\nimage out of a shared namespace.",
          "type": [
            "string",
            "null"
          ]
        },
        "repo": {
          "description": "Git remote: `https://…`, `ssh://…`, `git@host:path`, or a local path.\nMutually exclusive with `store`; exactly one must be set.\n\n`Option` rather than required because `store` is the alternative, not\nbecause a build can have no source — a spec with neither is refused. Every\nspec written before `store` existed has it, so nothing on disk needs\nmigrating.",
          "type": [
            "string",
            "null"
          ]
        },
        "store": {
          "description": "An artifact store holding a Dockerfile manifest: an `http(s)://` URL of an\n`art serve`, or an absolute store root on this host. Mutually exclusive\nwith `repo`.",
          "type": [
            "string",
            "null"
          ]
        }
      }
    },
    "DiscoverySource": {
      "type": "object",
      "properties": {
        "auth": {
          "$ref": "#/$defs/SecretRef"
        },
        "url": {
          "type": "string"
        }
      },
      "required": [
        "url",
        "auth"
      ]
    },
    "DiscoverySpec": {
      "type": "object",
      "properties": {
        "region": {
          "description": "Opt into region-scoped membership; the authority must echo this scope.",
          "type": [
            "string",
            "null"
          ]
        },
        "regional": {
          "anyOf": [
            {
              "$ref": "#/$defs/RegionalSpec"
            },
            {
              "type": "null"
            }
          ]
        },
        "service_id": {
          "type": "string"
        },
        "source": {
          "description": "Managed per-deployment authority; absent preserves the host env default.",
          "anyOf": [
            {
              "$ref": "#/$defs/DiscoverySource"
            },
            {
              "type": "null"
            }
          ]
        }
      },
      "required": [
        "service_id"
      ]
    },
    "Driver": {
      "description": "Which runtime boots a deployment's replicas.\n\napp-lb's own enum rather than [`heyo_sdk::SandboxDriver`], because not every\ndriver is a heyvm one: `lxc` is a system container app-lb creates on this\nhost through Incus, and the SDK has no name for it. The spellings are\ndeliberately identical to the SDK's, so a spec written against either\ndeserializes the same and the wire fixtures are unchanged.\n\n`Libvirt` and `FirecrackerContainerd` exist here only so that a spec naming\none still *deserializes* and is then refused by\n[`DeploymentSpec::validate`] with an explanation. Dropping the variants\nwould turn a good error message into an opaque serde failure.",
      "oneOf": [
        {
          "type": "string",
          "enum": [
            "firecracker",
            "kvm",
            "libvirt",
            "firecracker_containerd"
          ]
        },
        {
          "description": "A system container under Incus, booted from an OCI image. Not a heyvm\ndriver: app-lb talks to Incus itself, so [`Driver::heyvm`] is `None`.",
          "type": "string",
          "const": "lxc"
        }
      ]
    },
    "ExpectedHeader": {
      "description": "A response identity assertion, in addition to HTTP success.",
      "type": "object",
      "properties": {
        "name": {
          "type": "string"
        },
        "value": {
          "type": "string"
        }
      },
      "required": [
        "name",
        "value"
      ]
    },
    "FeedSpec": {
      "description": "A deployment's opt-in hooks into its namespace's event feed.\n\nEverything here defaults to *off*: the feed is a megaphone, and a\ndeployment should end up on it only because its spec said so, never because\na default did. The three switches are independent — a deployment can\nannounce itself without reporting issues, report issues without announcing,\nor neither and only `expose` the feed for the rest of its namespace.",
      "type": "object",
      "properties": {
        "announce": {
          "description": "Publish this deployment's lifecycle — registered, updated, removed — to\nthe namespace feed.",
          "type": "boolean",
          "default": false
        },
        "expose": {
          "description": "Serve the namespace's feed as RSS at this path on this deployment's own\nroutes. This is the only way a feed becomes reachable from outside the\nadmin listener: without an `expose` somewhere in the namespace, the feed\nstays private. Runs after the deployment's `auth` gate, so a gated\ndeployment exposes its feed only to whoever the gate admits.",
          "type": [
            "string",
            "null"
          ]
        },
        "issues": {
          "description": "Publish this deployment's operational issues — a VM that never boots, a\nfailed scale-up, a cold start that timed out, an upstream going\nunhealthy — to the namespace feed.",
          "type": "boolean",
          "default": false
        }
      }
    },
    "GatewayMode": {
      "type": "string",
      "enum": [
        "forward",
        "local"
      ]
    },
    "GatewaySpec": {
      "type": "object",
      "properties": {
        "auth": {
          "$ref": "#/$defs/SecretRef"
        },
        "mode": {
          "$ref": "#/$defs/GatewayMode"
        },
        "region": {
          "description": "Destination region for forward mode; this instance's region for local mode.",
          "type": "string"
        },
        "service": {
          "type": "string"
        }
      },
      "required": [
        "service",
        "region",
        "auth",
        "mode"
      ]
    },
    "HealthCheck": {
      "description": "How a freshly-booted VM is proven ready before it joins the pool.\n\nThis exists because the SDK's readiness signal is not trustworthy on its own\n(see `vm::wait_until_running`), so we always probe the guest ourselves.",
      "type": "object",
      "properties": {
        "expected_header": {
          "description": "With an identity assertion, require a 2xx response and exactly one\nmatching header. An old baked-in listener must not verify a new release.",
          "anyOf": [
            {
              "$ref": "#/$defs/ExpectedHeader"
            },
            {
              "type": "null"
            }
          ]
        },
        "path": {
          "description": "`None` means a bare TCP connect is enough.",
          "type": [
            "string",
            "null"
          ],
          "default": "/"
        },
        "port": {
          "description": "Health port, if the guest serves health somewhere other than `port`.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint16",
          "maximum": 65535,
          "minimum": 0
        },
        "timeout_secs": {
          "description": "How long a single probe may take before it counts as a failure.\nDefaults to 2.",
          "type": "integer",
          "format": "uint64",
          "default": 2,
          "minimum": 0
        }
      }
    },
    "IdleAction": {
      "description": "What becomes of a VM the autoscaler no longer needs.\n\nThe distinction only exists because a *sandbox* is not a replica. Retiring\none of four interchangeable web VMs should reclaim everything it held;\nretiring the single VM that is somebody's working directory should not.\n\nNote what `Retain` can and cannot keep: a stopped sandbox keeps its record\nand its **`/workspace` data disk** (`vm.disk_size_gb`), and loses its memory\nand any writes to the rootfs. For Firecracker the daemon enforces that —\nthe rootfs is recopied from the base image on every cold boot — and for KVM\nthe autoscaler does, by discarding the persisted rootfs copy right after a\nsuspend rather than parking a gigabyte per idle replica. A `Retain`\ndeployment with no data disk therefore saves boot time and nothing else.\nPersistent state has to live under `/workspace`.",
      "oneOf": [
        {
          "description": "Kill it: the sandbox, its data disk and its rootfs all go. The default,\nand right for a pool of interchangeable replicas.",
          "type": "string",
          "const": "destroy"
        },
        {
          "description": "Stop it: the sandbox stays, keeping its data disk, and a later request or\n`exec` resumes it instead of booting a fresh one.",
          "type": "string",
          "const": "retain"
        }
      ]
    },
    "IngressSpec": {
      "description": "How a managed deployment is reached from the Heyo cloud.\n\n`routes` are this proxy's business: a hostname the operator points at\n`APP_LB_PUBLIC_IPS`. A machine with no public address — a laptop, a box\nbehind NAT — has nothing to point a hostname at, and that is what this\nis for. With `cloud` set, app-lb binds every *ready* replica's `vm.port`\non the daemon as a proxy endpoint tagged with this deployment, and\nunbinds it when the replica drains. The daemon carries those binds to the\ncloud, and the cloud issues one URL for the deployment that fans out to\nwhichever binds exist at the moment — so the URL survives autoscaling,\nreplacement and a pool roll.\n\nTraffic on that URL never passes through this proxy: no `routes` match,\nno `auth` gate, no guard rule and no SIEM record. `public: false` puts\nthe cloud's own account gate in front of it instead.\n\nNot part of [`VmSpec`], so toggling it edits nothing about the VMs and\nnever recycles the pool.",
      "type": "object",
      "properties": {
        "cloud": {
          "description": "Ask the Heyo cloud for a URL, and keep the pool bound behind it.",
          "type": "boolean",
          "default": false
        },
        "public": {
          "description": "Whether that URL is reachable by anyone (the default) or only by the\nowning account, signed in to the cloud.",
          "type": "boolean",
          "default": true
        }
      }
    },
    "JwtSpec": {
      "description": "How a gate verifies a JWT, and which ones it lets past.\n\nThe block exists because a JWT gate is configuration all the way down. app-lb\ndid not issue the token and cannot ask anyone about it, so every question —\nwhich key, which algorithm, which issuer, which claim is the user, which\nclaims must hold — is something the spec has to answer. The upside of that is\nversatility: the Heyo auth API and an Auth0 tenant differ only in this block.\n\nA gate for the Heyo auth API is:\n\n```jsonc\n\"auth\": {\n  \"provider\": \"jwt\",\n  \"jwt\": {\n    \"secret\":     {\"secret\": \"heyo-auth\", \"key\": \"jwt_secret\"},\n    \"algorithms\": [\"HS256\"],\n    \"issuer\":     \"auth-service\",\n    \"audience\":   \"heyo-app\",\n    \"subject_claim\": \"userId\",\n    \"require\":    {\"role\": [\"user\", \"admin\"]}\n  }\n}\n```\n\nand the same gate in front of an OIDC provider is the same block with\n`jwks_url`, `RS256` and the default `sub`.\n\n## The allow-list is `require`, not `allowed_emails`\n\n[`AuthGate::allowed_domains`] and [`AuthGate::allowed_emails`] describe a\n*Google* identity: the domain is matched on the `hd` claim precisely because\nan email suffix proves nothing there. Neither statement transfers to a token\nfrom your own issuer, where the claims mean what that issuer says they mean —\nso a gate that accepts `jwt` without also accepting `google` is refused if it\nsets them, rather than appearing to restrict something it does not.\n\n`require` is the equivalent and it is more general: any claim, against a\nvalue or a set of them. An empty `require` admits any token the issuer signed\nfor this audience, which — unlike Google's empty allow-list, where the\npopulation is everyone with a Google account — is exactly \"a signed-in user\nof this product\", and a reasonable thing to want.\n\n## What is not here\n\nThere is no claim forwarding. The gate puts `x-auth-request-{email,user,name}`\nupstream like any other, and beyond that the application can read the token\nitself: it is still in the `Authorization` header the request arrived with,\nsigned, and the app already trusts the issuer or it would not be behind this\ngate. Copying claims into headers would only give it a second, weaker copy.",
      "type": "object",
      "properties": {
        "algorithms": {
          "description": "The signature algorithms this gate accepts, e.g. `[\"HS256\"]` or\n`[\"RS256\", \"ES256\"]`.\n\n**Required, with no default.** The algorithm is named in the token's own\nheader, which is attacker-controlled input, and a verifier that dispatches\non it accepts both an unsigned token (`alg: none`) and one signed with a\npublic key used as an HMAC secret. See [`crate::jwt`].",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "audience": {
          "description": "The `aud` a token must carry, if the issuer sets one. Matched against a\nstring audience or a member of an array one.",
          "type": [
            "string",
            "null"
          ]
        },
        "authorize_url": {
          "description": "**Scoped sign-in**: the issuer's OAuth 2.0 authorization endpoint, for a\nbrowser that reaches this gate with no session. Set together with\n[`token_url`](Self::token_url); the Heyo auth API serves both at\n`/oauth/authorize` and `/oauth/token`.\n\nThe difference from [`login_url`](Self::login_url) is where the\ncredential ends up. With `login_url` the issuer leaves its token in a\ncookie on a domain it shares with this host, so every host under that\ndomain — other tenants' deployments included — receives it. With this,\napp-lb asks the issuer for access to *this deployment's namespace*\n(`scope=namespace:<ns>`, plus PKCE `S256` and `state`), the issuer\ndecides whether the person may reach it, and the code it returns is\nexchanged server to server for a token naming this one host\n(`gateHost`) and namespace. The gate verifies it against this policy,\nchecks both claims, and keeps its own host-only session; the token never\nsits in a browser at all.\n\nMust be `https://` (or loopback `http://`). Cannot be combined with a\nshared session realm (`cookie_domain`): a session issued for one\nnamespace must not be honoured by a sibling gate in another.",
          "type": [
            "string",
            "null"
          ]
        },
        "cookie": {
          "description": "A cookie to read the token from when there is no `Authorization` header.\n\nFor a browser application whose sign-in put the JWT in a cookie — common,\nand the only way a page navigation can carry a credential at all, since a\nbrowser cannot set a header on one. The `Authorization` header still wins\nwhen both are present: a request that says what it is presenting means it.",
          "type": [
            "string",
            "null"
          ]
        },
        "email_claim": {
          "description": "Which claim holds the address forwarded as `x-auth-request-email`.",
          "type": "string",
          "default": "email"
        },
        "issuer": {
          "description": "The `iss` a token must carry, exactly.\n\nRequired, because a signature proves only that *a* holder of the key\nsigned the token — and with a shared secret that is every service the\nsecret was ever handed to.",
          "type": "string"
        },
        "jwks_url": {
          "description": "The issuer's JWKS endpoint, usually `<issuer>/.well-known/jwks.json`.\n\nThe right choice for any provider that rotates keys: the set is fetched,\ncached for ten minutes, and refetched when a token names a `kid` that is\nnot in it — so a rotation needs nothing done here.",
          "type": [
            "string",
            "null"
          ]
        },
        "leeway_secs": {
          "description": "Clock skew allowed on `exp` and `nbf`, in seconds. Capped at\n[`MAX_JWT_LEEWAY_SECS`].",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint64",
          "minimum": 0
        },
        "login_endpoint": {
          "description": "Optional Heyo Auth `/api/auth/login` endpoint for browser email/password\nsign-in. The returned access token must pass this JWT policy before a\nhost-only HttpOnly cookie is set. Requires `cookie`; never stores refresh\ntokens or passwords. Existing bearer-only gates remain unchanged.",
          "type": [
            "string",
            "null"
          ]
        },
        "login_redirect_param": {
          "description": "The query parameter the hosted sign-in reads the return URL from. Only\nmeaningful with `login_url`; unset means `redirect_uri`. Set it to whatever\nthe issuer expects — `return_to`, `next`, `rd`.",
          "type": [
            "string",
            "null"
          ]
        },
        "login_url": {
          "description": "Where to send a browser that reaches a gated path holding no valid token.\n\nThe `jwt` provider is otherwise stateless: it verifies a token that is\nalready being carried and, finding none, answers `401`. That is right for\na program, and a dead end for a person — a browser cannot set an\n`Authorization` header on a navigation, so it has no way to *acquire* one.\n\nSet this to the issuer's hosted sign-in page and a token-less **browser**\n(a request whose `Accept` includes HTML) is redirected there instead, with\nthe URL it was trying to reach passed in `login_redirect_param`. The issuer\nsigns the user in, sets the JWT in the `cookie` named above, and redirects\nback; the gate then reads the cookie and admits the request. app-lb mints\nno session and keeps no flow state — the cookie the issuer set *is* the\nsession. A program (no HTML in `Accept`) still gets the `401`, which it can\nact on and would only fail to parse as a sign-in page.\n\nRequires `cookie`: the return trip is a navigation, and a navigation can\ncarry a credential only in a cookie ([`SpecError::LoginUrlWithoutCookie`]).\nMust be `https://` (or a loopback `http://` for an issuer on this host),\nfor the same reason `jwks_url` must.",
          "type": [
            "string",
            "null"
          ]
        },
        "name_claim": {
          "description": "Which claim holds the display name. Absent from most tokens, and absent\nhere means the header is simply not sent.",
          "type": "string",
          "default": "name"
        },
        "public_key": {
          "description": "A PEM public key or certificate, inline. For the `RS*`, `PS*` and `ES*`\nalgorithms when the issuer publishes one key rather than a key set.\n\nInline rather than a [`SecretRef`] because it is a *public* key: putting\nit in the secret store would imply it needs protecting and make rotating\nit a two-step operation for no gain.",
          "type": [
            "string",
            "null"
          ]
        },
        "require": {
          "description": "Claims a token must satisfy, on top of being validly signed.\n\nA value or a list of them per claim: a list is an OR within that claim,\nand the map is an AND across claims. A claim that is *itself* a list —\nscopes, roles, groups — is satisfied when it contains one of the wanted\nvalues, which is what makes `{\"scopes\": \"deploy\"}` mean what it looks\nlike.",
          "type": "object",
          "additionalProperties": true
        },
        "secret": {
          "description": "The HMAC shared secret, as a reference into the secret store. For the\n`HS*` algorithms, and the shape the Heyo auth API uses (`JWT_SECRET`).\n\nA reference rather than a literal for the usual reason, and one specific\nto this: the same value verifies *and mints* tokens, so a spec carrying it\nwould hand anyone who can read a deployment the ability to issue\nidentities.",
          "anyOf": [
            {
              "$ref": "#/$defs/SecretRef"
            },
            {
              "type": "null"
            }
          ]
        },
        "subject_claim": {
          "description": "Which claim holds the stable user id forwarded as `x-auth-request-user`.\n`sub` unless the issuer says otherwise — the Heyo auth API uses `userId`.",
          "type": "string",
          "default": "sub"
        },
        "token_url": {
          "description": "The issuer's token endpoint, which the gate calls server to server to\nredeem the code from [`authorize_url`](Self::authorize_url).",
          "type": [
            "string",
            "null"
          ]
        }
      },
      "required": [
        "algorithms",
        "issuer"
      ]
    },
    "MountSpec": {
      "description": "A directory every replica boots with, unpacked from a tarball in an artifact\nstore.\n\nThe third thing app-lb pulls out of a store, and the only one that is neither\nthe image nor the site. [`ArtifactSpec`] materializes a *rootfs* the guest\nboots from; a [`SiteSpec`] pull lands a tree on **this** host and serves it;\nthis lands a tree **inside** the guest, beside a rootfs it did not come from.\n\nThat separation is the whole point. A dataset, a model, a seed corpus or a\nbundle of assets moves on its own schedule, and shipping it inside the rootfs\nwelds the two together: a new copy of a 4 GB corpus becomes a new image,\nevery host re-pulls the operating system to get it, and a rollback of one is\na rollback of both. As a mount it is its own digest, pulled once per host and\nshared by every replica that names it.\n\n## How it reaches the guest\n\napp-lb resolves the reference, verifies the blob against its digest, and\nunpacks it into a directory on this host named after that digest. The daemon\nis given the directory, not the tarball: at boot heyvmd builds an ext4 image\nfrom it (`mke2fs -d`) and attaches it as a virtio-blk device that the guest's\ninit mounts at [`path`](Self::path) *before* the start command runs, so a\nworkload can read it on its first line.\n\nTwo consequences the spec does not show:\n\n* **The disk is per VM.** Every replica gets its own image built from the\n  same tree, so no guest can see another's writes and the tree itself is only\n  ever read.\n* **A mount is boot-time only.** There is no hot-add, which is why this is\n  part of [`VmSpec`]: editing the list is a template change, and a template\n  change recycles the pool.\n\n## Why the tree is not fetched when the VM is created\n\nThe autoscaler creates VMs inside its reconcile tick, and a create that first\nfetched gigabytes would stall every deployment on the host behind one. So the\nfetch is a job — `POST /deployments/:id/mounts/pull` — which resolves the\nreference, unpacks the tree once, writes the resolved [`digest`](Self::digest)\nback into this block and recycles the pool onto it. Until that has happened\nthere is no tree to mount, and the autoscaler refuses to create replicas\nrather than booting one that is silently missing its data.\n\nOne is started automatically when a deployment with mounts is registered or\nedited, so the usual path is: `POST /deployments` → a pull job → a pool.",
      "type": "object",
      "properties": {
        "auth": {
          "description": "API key for a store started with `ART_API_KEY`, as a reference into the\nsecret store. Only meaningful for the URL form.",
          "anyOf": [
            {
              "$ref": "#/$defs/SecretRef"
            },
            {
              "type": "null"
            }
          ]
        },
        "digest": {
          "description": "What [`artifact_ref`](Self::artifact_ref) resolved to, written by the pull\njob. The answer to \"which bytes is this deployment mounting?\", and the\nname of the tree on disk.\n\nAbsent means nothing has been pulled yet and the pool cannot be created;\nsee the module note above. Setting it by hand pins the mount to a tree\nalready on this host, which is what an edit that must not re-fetch looks\nlike — a spec whose digest names no tree is rejected at registration, not\ndiscovered at boot.",
          "type": [
            "string",
            "null"
          ]
        },
        "path": {
          "description": "Where the tree appears inside the guest: an absolute path, created if it\ndoes not exist.\n\nAlso the identity of the mount within the deployment — two mounts cannot\nname the same path, and one cannot sit inside another, because the guest\nmounts them in order and the second would hide the first.",
          "type": "string"
        },
        "read_only": {
          "description": "Whether the guest mounts it read-only. Defaults to **true**: the tree is\ndata the deployment was given, and a replica that can scribble on its own\ncopy of it makes \"which bytes is this VM serving?\" a question with a\nper-VM answer.\n\nWritable is allowed on `firecracker`, where each VM's ext4 image is its\nown and nothing propagates back to the host tree. It is **refused on\n`kvm`**, whose driver syncs a read-write mount image back into the host\ndirectory when the VM stops — and that directory is the shared,\ncontent-addressed tree every other replica is booting from, so one\nreplica's writes would rewrite what the digest names.",
          "type": "boolean",
          "default": true
        },
        "ref": {
          "description": "A tag or a 64-hex digest naming a `tar` or `tar.gz` of the directory.\n\nA tag is resolved every time the pull job runs, so a mount pinned to one\nfollows it; a digest is immutable and is what a rollback names. This is\nthe same bundle shape a site pulls — `art put data.tgz --tag corpus-v3`\nputs one in.",
          "type": "string"
        },
        "store": {
          "description": "The store to pull from: an `http(s)://` `art serve`, or a store root on\nthis host. Exactly as [`ArtifactSpec::store`], including which of the two\ntransports each spelling selects.",
          "type": "string"
        },
        "strip_components": {
          "description": "Leading path components to drop while unpacking, as\n`tar --strip-components` does — and needed for the same reason\n[`ArtifactSpec::strip_components`] is: `tar czf corpus.tgz corpus` writes\nevery entry as `corpus/…`, so without a `1` here the guest finds its data\nat `<path>/corpus` instead of at `<path>`.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint",
          "minimum": 0
        }
      },
      "required": [
        "path",
        "store",
        "ref"
      ]
    },
    "PathScope": {
      "description": "What app-lb requires on a path the sign-in gate does not cover.\n\nThe three lower tiers mirror [`crate::tokens::AdminScope`] exactly, because\nthey are the same scopes an app-token carries; `Public` is the extra one,\nand it is the only value that admits a request presenting nothing.",
      "oneOf": [
        {
          "description": "No credential at all. For a path whose upstream authorizes it, or one\nthat genuinely has nothing to protect — a health endpoint.",
          "type": "string",
          "const": "public"
        },
        {
          "description": "Any credential the gate would admit, with no admin tier required. What\nan app-token minted with `admin: none` carries, which is the shape an\napplication is handed to get past its own deployment's gate.",
          "type": "string",
          "const": "none"
        },
        {
          "description": "`view`-tier: metrics and the dashboard's data.",
          "type": "string",
          "const": "view"
        },
        {
          "description": "Everything. The default when a scope is not written down, because a\nforgotten field must not be the one that opens a route.",
          "type": "string",
          "const": "admin"
        }
      ]
    },
    "Providers": {
      "description": "One provider, or several. A single provider is written as a bare string so a gate authored before app-tokens existed round-trips unchanged.",
      "anyOf": [
        {
          "$ref": "#/$defs/AuthProvider"
        },
        {
          "type": "array",
          "items": {
            "$ref": "#/$defs/AuthProvider"
          }
        }
      ]
    },
    "PublicPath": {
      "description": "A path exempted from the gate, as either a bare string or an object. A BARE STRING MEANS scope \"admin\" — the most closed scope, not the most open one — so an entry written as a plain path is reachable only by an admin credential.",
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "object",
          "properties": {
            "path": {
              "type": "string"
            },
            "scope": {
              "$ref": "#/$defs/PathScope"
            }
          },
          "required": [
            "path"
          ]
        }
      ]
    },
    "RegionalSpec": {
      "type": "object",
      "properties": {
        "auth": {
          "$ref": "#/$defs/SecretRef"
        },
        "backend_server_id": {
          "type": "string"
        },
        "environment": {
          "type": "string"
        },
        "gateway_id": {
          "type": "string"
        }
      },
      "required": [
        "gateway_id",
        "backend_server_id",
        "environment",
        "auth"
      ]
    },
    "RootfsMode": {
      "description": "See [`VmSpec::rootfs`].",
      "oneOf": [
        {
          "description": "A private, writable copy of the image per boot.",
          "type": "string",
          "const": "copy"
        },
        {
          "description": "The image itself, attached read-only; no copy.",
          "type": "string",
          "const": "shared"
        }
      ]
    },
    "RouteRule": {
      "description": "How a request is matched to a deployment.\n\nA rule matches when *every* populated field matches. An empty rule matches\nnothing (rejected at registration) rather than everything, so a typo can't\nsilently swallow all traffic.",
      "type": "object",
      "properties": {
        "host": {
          "description": "Exact hostname match, case-insensitive, port stripped. For HTTP/2 this\nis matched against `:authority`, which carries no `Host` header.",
          "type": [
            "string",
            "null"
          ]
        },
        "host_suffix": {
          "description": "Subdomain (wildcard) host match: a domain whose apex *and* any subdomain\nmatch — `host_suffix: \"apps.example.com\"` routes `apps.example.com`,\n`a.apps.example.com`, and `x.y.apps.example.com`, but not\n`notapps.example.com` (the match is anchored at a label boundary). A\nleading dot is accepted and ignored, so `.apps.example.com` is equivalent.\nAn exact `host` always outranks a `host_suffix`, and a longer suffix\noutranks a shorter one.",
          "type": [
            "string",
            "null"
          ]
        },
        "path_prefix": {
          "description": "Path prefix match, e.g. `/api`.",
          "type": [
            "string",
            "null"
          ]
        },
        "strip_prefix": {
          "description": "Remove `path_prefix` before forwarding to the upstream. Off by default,\npreserving the original pass-through behavior for existing specs.",
          "type": "boolean"
        }
      }
    },
    "SandboxSize": {
      "description": "`heyo_sdk::SandboxSize`, mirrored for schema generation only.\n\nThe real type is in another crate and cannot carry a derive from this one.\nA mirror is the drift risk this whole generator exists to remove, so it is\nkept to the one thing that cannot be avoided — six unit variants — and the\ncrate that owns them is named here so a version bump has somewhere to look.\nNothing deserializes through it; it exists to be pointed at by `schemars(with)`.",
      "type": "string",
      "enum": [
        "micro",
        "mini",
        "small",
        "medium",
        "large",
        "xlarge"
      ]
    },
    "ScalingPolicy": {
      "type": "object",
      "properties": {
        "boot_timeout_secs": {
          "description": "How long a booting VM has to pass its health check before the autoscaler\ngives up on it, kills it and lets the next tick create a replacement.\n\nWithout a deadline here a VM that boots but never serves — the daemon says\n`Running`, the guest's process died or never started — is re-queued every\ntick indefinitely, so the deployment sits at zero replicas with no error\nanywhere. The pool's own `min_replicas` can never be met and nothing says\nwhy. `0` restores that unbounded wait for a deployment whose boots are\ngenuinely open-ended.\n\nReplacements back off. Consecutive failed boots — timeouts and terminal\nstatuses alike — delay the next create, doubling from thirty seconds to\nan hour and resetting on the first healthy boot (see\n[`crate::deployment::boot_backoff_secs`]). Without that, a guest that\ncan never become ready churns a fresh sandbox — and, historically, a\nfresh set of leaked disk directories — per cycle, forever.",
          "type": "integer",
          "format": "uint64",
          "default": 300,
          "minimum": 0
        },
        "cold_start_timeout_secs": {
          "description": "How long a request will wait for a VM to boot before giving up with 503.",
          "type": "integer",
          "format": "uint64",
          "default": 120,
          "minimum": 0
        },
        "drain_timeout_secs": {
          "description": "How long a draining VM may keep serving in-flight requests before it is\nkilled anyway.",
          "type": "integer",
          "format": "uint64",
          "default": 30,
          "minimum": 0
        },
        "idle_action": {
          "description": "Whether a VM the autoscaler retires is destroyed or merely stopped. See\n[`IdleAction`]; defaults to `destroy`, which is the historical behaviour.",
          "$ref": "#/$defs/IdleAction",
          "default": "destroy"
        },
        "max_replicas": {
          "description": "Ceiling on replicas the autoscaler may run. Defaults to 5. Must be at most 1\nwhen [`VmSpec::workspace`] is set — a single-writer workspace cannot\nhave two replicas capturing divergent copies of it.",
          "type": "integer",
          "format": "uint32",
          "default": 5,
          "minimum": 0
        },
        "min_replicas": {
          "description": "Replicas kept running even with no traffic. Defaults to 0, which lets\nthe pool scale to zero and makes the next request pay a cold start.",
          "type": "integer",
          "format": "uint32",
          "default": 0,
          "minimum": 0
        },
        "scale_to_zero_after_secs": {
          "description": "Idle seconds before a pool with `min_replicas: 0` and no warm pool is\ntorn down entirely. Defaults to 300; `0` means the pool tears down on\nthe first idle tick.",
          "type": "integer",
          "format": "uint64",
          "default": 300,
          "minimum": 0
        },
        "target_concurrency": {
          "description": "In-flight requests per VM the autoscaler aims for.",
          "type": "integer",
          "format": "uint32",
          "default": 10,
          "minimum": 0
        },
        "warm_pool": {
          "description": "Idle-but-ready spares kept above what current load requires.",
          "type": "integer",
          "format": "uint32",
          "default": 0,
          "minimum": 0
        }
      }
    },
    "SecretEnv": {
      "description": "One secret value, exported to the update commands as an environment variable.",
      "type": "object",
      "properties": {
        "as": {
          "description": "Variable name. Defaults to the key, upper-cased — `{\"secret\": \"obs\",\n\"key\": \"ingest_token\"}` arrives as `INGEST_TOKEN`.",
          "type": [
            "string",
            "null"
          ]
        },
        "key": {
          "type": "string",
          "default": "token"
        },
        "namespace": {
          "description": "The namespace the secret lives in; stamped from the deployment's, see\n[`SecretRef::namespace`].",
          "type": [
            "string",
            "null"
          ]
        },
        "secret": {
          "type": "string"
        }
      },
      "required": [
        "secret"
      ]
    },
    "SecretRef": {
      "description": "A pointer to one value inside one secret, as a deployment spec spells it.\n\nDeliberately not a value: a spec holding `{\"secret\": \"github\", \"key\":\n\"token\"}` can be read, edited, backed up and diffed without ever carrying the\ncredential, and the indirection is what lets the token be rotated in one\nplace for every deployment that builds from that repo.",
      "type": "object",
      "properties": {
        "key": {
          "description": "Which key inside it. Defaults to `token`, the only key a git credential\nnormally needs.",
          "type": "string",
          "default": "token"
        },
        "namespace": {
          "description": "The namespace the secret lives in.\n\nStamped from the deployment's own namespace when a spec is registered\n(see `DeploymentSpec::normalize`), never taken from the client: a spec\nin `team-a` resolves `team-a`'s `github`, whatever the body said, which\nis the whole wall. Absent on state files written before namespaces\nexisted and read as [`DEFAULT_NAMESPACE`].",
          "type": [
            "string",
            "null"
          ]
        },
        "secret": {
          "description": "The secret's id.",
          "type": "string"
        },
        "username": {
          "description": "Username to pair the value with, for the (rare) forge that wants a real\none. GitHub, GitLab and Bitbucket all accept a placeholder next to a PAT,\nwhich is why this defaults rather than being asked for.",
          "type": [
            "string",
            "null"
          ]
        }
      },
      "required": [
        "secret"
      ]
    },
    "SiteSpec": {
      "description": "A static *site*: a directory on this host, served straight off disk.\n\nThe third backend kind, and the one with no backend — app-lb answers the\nrequest itself instead of proxying it. What nginx's `root` or a CloudFront\norigin bucket does: files, an index, a 404, and cache headers. There is no\npool, nothing to scale, and nothing to health check.\n\nDeliberately not configurable: rewrites, redirects, per-location blocks. A\nsite that needs those wants a real server behind a `proxy_pass` deployment.",
      "type": "object",
      "properties": {
        "cache_control": {
          "description": "`Cache-Control` for served files. The default is deliberately short:\na wrong long max-age is not something you can take back, since the\nclient will not ask again until it expires.",
          "type": "string",
          "default": "public, max-age=300"
        },
        "index": {
          "description": "Served for a request that names a directory. Set to `\"\"` to answer those\nwith a 404 instead of looking for an index.",
          "type": "string",
          "default": "index.html"
        },
        "not_found": {
          "description": "Body for a 404, relative to `root`. Absent means a plain-text 404.",
          "type": [
            "string",
            "null"
          ]
        },
        "root": {
          "description": "Absolute path ON THE APP-LB HOST to the directory to serve. Nothing\noutside it is ever served, symlinks included — see `site::resolve`.\n\nOmit it to have app-lb choose `<APP_LB_SITES_DIR>/<namespace>/<id>`,\nwhich is what a site filled by `build` or `artifact` wants: the caller\ncannot see this host's filesystem, and a path that exists only on the\ncaller's machine registers fine and then 404s every request.",
          "type": "string",
          "default": ""
        },
        "spa": {
          "description": "Serve `index` (with a 200) for any path that matches no file, so a\nclient-side router owns the URL space. The single-page-app switch; off\nby default because it turns every typo into a 200.",
          "type": "boolean",
          "default": false
        }
      }
    },
    "UpdateSpec": {
      "description": "How a *static* (proxy_pass) deployment's backend is updated: a working\ndirectory on the app-lb host, and commands to run in it.\n\nThe managed counterpart of this is [`BuildSpec`], and the asymmetry is the\npoint. A managed deployment's backend is a microVM app-lb owns, so updating\nit means producing a new image. A static deployment's backend is a process\nsomebody else runs — usually on this same host, under supervisord or systemd\n— so updating it means doing on the host what a person would otherwise ssh in\nand do: pull, build, restart.\n\nNothing in the spec changes when this runs. The upstreams are the same\naddresses; what moved is the code answering on them. That is why the job\nre-probes those addresses afterwards: \"the commands exited 0\" is not the same\nclaim as \"the service is serving\".",
      "type": "object",
      "properties": {
        "auth": {
          "description": "Git credential for commands that fetch (`git pull`), supplied through\n`GIT_ASKPASS`. Only meaningful for HTTP(S) remotes.",
          "anyOf": [
            {
              "$ref": "#/$defs/SecretRef"
            },
            {
              "type": "null"
            }
          ]
        },
        "commands": {
          "description": "Commands, run in order, each through `sh -c` in `working_dir`. The first\nnon-zero exit stops the job.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "env": {
          "description": "Extra environment for every command.",
          "type": [
            "object",
            "null"
          ],
          "additionalProperties": {
            "type": "string"
          }
        },
        "env_from": {
          "description": "Environment pulled from the secret store, so a deploy key or registry\ntoken reaches the commands without being written into this spec.",
          "type": "array",
          "items": {
            "$ref": "#/$defs/SecretEnv"
          }
        },
        "timeout_secs": {
          "description": "Ceiling on a single command. Defaults to `APP_LB_BUILD_TIMEOUT_SECS`.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint64",
          "minimum": 0
        },
        "verify_timeout_secs": {
          "description": "How long to wait, after the commands, for every upstream to answer its\nhealth check. `0` skips verification — appropriate when the commands do\nnot restart anything, and wrong otherwise.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint64",
          "minimum": 0
        },
        "working_dir": {
          "description": "Absolute path on the app-lb host. Must exist when the job runs — app-lb\nnever creates it, because a typo that silently created an empty directory\nand ran `git pull` in it would be worse than an error.",
          "type": "string"
        }
      },
      "required": [
        "working_dir",
        "commands"
      ]
    },
    "VmSpec": {
      "description": "The VM template. Mirrors `SandboxCreateOptions`, minus the fields the LB owns\n(`name` is generated per-replica; `wait_for_ready` is always zero because the\nautoscaler polls readiness itself rather than blocking its reconcile loop).\n\nNote the SDK cannot express vcpu/memory directly — `size_class` is the only\nresource knob, and the daemon resolves it host-side. It cannot express\n`mounts` either, which is why [`crate::vm::VmManager::create`] builds the\ncreate body itself rather than handing the SDK a `SandboxCreateOptions`.\n`PartialEq` is load-bearing: an in-place edit keeps the running pool only\nwhen the VM *template* is unchanged, so the update path compares old and new\n`VmSpec`s to decide whether the VMs must be rebuilt.",
      "type": "object",
      "properties": {
        "correlated_creates": {
          "description": "Require durable heyvmd operation receipts for autoscaler allocations.\nRequires an internal daemon credential and /sandbox-creations support;\nunknown outcomes never fall back to legacy create or name matching.",
          "type": "boolean"
        },
        "disk_size_gb": {
          "description": "Size of the replica's persistent data disk, mounted at `/workspace`.\n\nSeparate from the rootfs, which is fixed when the image is built and\ncannot be grown afterwards — so this is not the knob for \"the image ran\nout of space\". The disk belongs to one sandbox: a rollout, a restart or\nany `vm` edit boots a replica with a fresh one, and only\n[`WorkspaceSpec`] carries contents across.",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint32",
          "minimum": 0
        },
        "driver": {
          "description": "`firecracker` or `kvm` (a heyvm microVM) or `lxc` (an Incus system\ncontainer from an OCI image). `libvirt` and `firecracker_containerd`\nare rejected at registration.",
          "$ref": "#/$defs/Driver"
        },
        "env_from": {
          "description": "Secret values exported to every replica as environment variables,\nresolved when the VM is created. The spec carries the reference and the\nstore the value, which is what keeps a token out of `GET /deployments`\nand out of the state file — the reason `env_vars` is the wrong place\nfor one.",
          "type": "array",
          "items": {
            "$ref": "#/$defs/SecretEnv"
          }
        },
        "env_vars": {
          "description": "Plain environment variables for every replica.\n\nStored in the spec as written, so they are readable from\n`GET /deployments` and from the state file on disk. Anything secret\nbelongs in [`env_from`](Self::env_from), which resolves from the secret\nstore at create time and keeps the value out of both.",
          "type": [
            "object",
            "null"
          ],
          "additionalProperties": {
            "type": "string"
          }
        },
        "image": {
          "description": "Defaults to `ubuntu:24.04` daemon-side when unset.",
          "type": [
            "string",
            "null"
          ]
        },
        "image_download_url": {
          "description": "Where the daemon may fetch `image` from when it does not already hold\nit: a public-image catalog URL, with the size and digest the daemon\nverifies the download against. Filled in by cloud's namespace door\nfrom its catalog and passed to the daemon untouched; a spec written by\nhand against a local daemon leaves all three unset.",
          "type": [
            "string",
            "null"
          ]
        },
        "image_sha256": {
          "type": [
            "string",
            "null"
          ]
        },
        "image_size_bytes": {
          "type": [
            "integer",
            "null"
          ],
          "format": "uint64",
          "minimum": 0
        },
        "mounts": {
          "description": "Directories handed to every replica, unpacked from tarballs in an\nartifact store. See [`MountSpec`].\n\nPart of the *template* rather than a block of its own, because a mount is\nattached at boot and can never be added to a VM that is already running —\nso changing this list has to recycle the pool, and being here is what\nmakes that happen.",
          "type": "array",
          "items": {
            "$ref": "#/$defs/MountSpec"
          }
        },
        "open_ports": {
          "description": "Guest ports to open *in addition to* [`port`](Self::port), which is\nadded automatically.\n\nFor a service reached on more than the one port the proxy forwards to —\na broker with a client port beside its monitoring port, say.",
          "type": "array",
          "items": {
            "type": "integer",
            "format": "uint16",
            "maximum": 65535,
            "minimum": 0
          }
        },
        "port": {
          "description": "The guest port traffic is proxied to.",
          "type": "integer",
          "format": "uint16",
          "maximum": 65535,
          "minimum": 0
        },
        "rootfs": {
          "description": "How the VM's root filesystem relates to its image.\n\n`copy` (the default) boots from a private copy of the image that heyvm\nmakes on every cold boot — a reflink where the filesystem can, a full\ncopy where it cannot (ext4). `shared` attaches the image itself\nread-only, so no copy is made at all: the image must bring its own\nwritable layer (the hub's base images mount tmpfs over the paths that\nneed writing), and anything that must persist lives on the data disk or\nthe workspace mount. The reuse a `/workspace` VM wants.\n\nheyvm versions without per-sandbox `rootfs_mode` ignore it and copy.",
          "$ref": "#/$defs/RootfsMode"
        },
        "setup_hooks": {
          "type": [
            "array",
            "null"
          ],
          "items": {
            "type": "string"
          }
        },
        "size_class": {
          "description": "CPU and memory, as one of the daemon's named classes.\n\nThe only resource knob the SDK has — vcpu and memory cannot be set\ndirectly — and the daemon resolves it host-side. Unset takes the\ndaemon's default. On `lxc` the host mapping runs micro (1 CPU, 512 MiB)\nthrough xlarge (8 CPU, 16 GiB), and unset there means `small`.",
          "anyOf": [
            {
              "$ref": "#/$defs/SandboxSize"
            },
            {
              "type": "null"
            }
          ]
        },
        "start_command": {
          "description": "Shell command that starts the workload, run once per replica after boot.\n\nRequired to run anything: a VM never runs its image's `CMD` or\n`ENTRYPOINT` (the rootfs is a `docker export`, which drops the image\nconfig), so without this the guest boots, nothing listens, and every\nreplica times out. Put what `CMD` did here, `WORKDIR` and `ENV`\nincluded, e.g. `cd /app && setsid nohup node server.js </dev/null &`.\n\nIt must *return*: the daemon runs it and waits, so a command that blocks\nin the foreground is a VM that never finishes booting. Daemonize\nexplicitly with `setsid nohup <program> </dev/null &`. Its stdout and\nstderr go to `/var/log/heyvm-start.log` and `.err.log` inside the guest,\nand on to app-obs when the image has `socat`; don't redirect them to a\nfile of your own, or they never leave the guest.",
          "type": [
            "string",
            "null"
          ]
        },
        "ttl_seconds": {
          "description": "Backstop TTL so VMs die on their own if this LB crashes and never reaps\nthem. Renewed by the autoscaler while it is alive.",
          "type": "integer",
          "format": "uint64",
          "default": 3600,
          "minimum": 0
        },
        "working_directory": {
          "description": "Directory `start_command` runs in. Defaults to the guest's own default.",
          "type": [
            "string",
            "null"
          ]
        },
        "workspace": {
          "description": "A writable directory that belongs to the *deployment* rather than to any\none VM: captured when a replica retires and seeded into the next one, so\nits contents survive restarts, rebuilds and rollouts. See\n[`WorkspaceSpec`].\n\nIn the template for the same reason `mounts` is: it is attached at boot,\nand a VM booted without it has nowhere to put the state the next VM is\nsupposed to inherit.",
          "anyOf": [
            {
              "$ref": "#/$defs/WorkspaceSpec"
            },
            {
              "type": "null"
            }
          ]
        },
        "workspace_archive": {
          "description": "A tarball to seed `/workspace` from on every replica boot. See\n[`WorkspaceArchive`]. Unlike [`workspace`](Self::workspace) nothing is\ncaptured back: each replica starts from the same snapshot, so this\ncomposes with a pool of any size.",
          "anyOf": [
            {
              "$ref": "#/$defs/WorkspaceArchive"
            },
            {
              "type": "null"
            }
          ]
        }
      },
      "required": [
        "driver",
        "port"
      ]
    },
    "WorkspaceArchive": {
      "description": "A workspace archive — a gzipped tarball in the runtime object store — that\nevery replica's `/workspace` is unpacked from at boot.\n\nA client names it by `archive_id`, the id cloud handed out when the archive\nwas uploaded or captured. Cloud's namespace door owns those ids: it checks\nthe caller owns the archive and fills in `s3_key`, which is what the daemon\nactually fetches (`POST /sandbox-deploy` with `s3_archive_key`). app-lb\nrefuses a spec that reaches it with the id alone rather than guessing at\na key — a wrong guess would boot a replica with someone else's files.",
      "type": "object",
      "properties": {
        "archive_id": {
          "type": [
            "string",
            "null"
          ]
        },
        "s3_key": {
          "type": [
            "string",
            "null"
          ]
        },
        "size_bytes": {
          "type": [
            "integer",
            "null"
          ],
          "format": "uint64",
          "minimum": 0
        }
      }
    },
    "WorkspaceSpec": {
      "description": "A persistent, writable workspace owned by the deployment.\n\nThe fourth thing app-lb moves between a store and a guest, and the only one\nthat moves in **both directions**. A [`MountSpec`] is data the deployment\nwas *given*; a workspace is data the deployment *makes* — the agent's\nsessions, the repositories it cloned, the files it was asked to keep — and\nit has to outlive the VM that wrote it. heyvm's own `/workspace` data disk\ndoes not: it belongs to one sandbox, so every rollout, every `restart`, and\nevery rebuild that recycles the pool boots a replica with an empty one.\n\n## The lifecycle\n\n* **Seed.** When the autoscaler creates a replica it hands heyvmd the\n  workspace's current tree on this host as a writable mount at\n  [`path`](Self::path). The daemon builds the VM its own ext4 image from\n  that tree (`mke2fs -d`), so the guest writes to a block device and the\n  tree itself is only read. With no tree yet — a fresh host, or a swept\n  one — the latest snapshot is pulled from [`store`](Self::store) first;\n  with no snapshot in the store either, the workspace starts empty.\n* **Capture.** When a replica retires for any reason — drained by a\n  rollout, evicted, torn down by an edit or a deregistration, suspended by\n  `idle_action: retain` — app-lb syncs the guest, stops the VM, replays the\n  image's journal, extracts it into a new tree, and points the deployment\n  at that tree. The replacement is not created until that has happened,\n  which is the whole guarantee: the next VM boots from the last VM's final\n  state, not from whatever the store held when the host came up.\n* **Push.** Each capture is bundled (`tar.gz`, named by its sha256) and sent\n  to the store under [`ref`](Self::artifact_ref), so the workspace survives\n  the host too. A push that fails is retried; it never blocks the rollout,\n  because the tree the next VM needs is already here.\n\n## What this costs, and what it refuses\n\nA capture stops the VM, so a rollout of a workspace deployment has a gap:\nthe old replica is drained and stopped, its tree is extracted, and only then\ndoes the new one boot. That is inherent to single-writer state and it is why\n`scaling.max_replicas` **must be at most 1** — two replicas would each capture their\nown divergent copy and the last one to land would win. `warm_pool` must be\n`0` for the same reason, and the driver must be `firecracker`: the KVM\ndriver has its own idea of what a writable mount means when the VM stops.\n\nOwnership is flattened: the tree is extracted and rebuilt by app-lb's own\nuser, so every file comes back owned by that uid inside the guest. A\nworkload that runs as root reads and writes them regardless; one that\nchecks ownership (git's `safe.directory`, Postgres's data-directory check)\nneeds to be told. Modes, symlinks and timestamps survive.",
      "type": "object",
      "properties": {
        "auth": {
          "description": "Credentials for the store, as a secret reference. Artifact stores only;\nthe `aws` CLI reads its own.",
          "anyOf": [
            {
              "$ref": "#/$defs/SecretRef"
            },
            {
              "type": "null"
            }
          ]
        },
        "path": {
          "description": "Where the workspace appears inside the guest. Defaults to\n[`DEFAULT_WORKSPACE_PATH`], which is also the only path heyvmd sizes from\n`disk_size_gb`; anywhere else gets 1.5× its content with a 2 GiB floor.",
          "type": [
            "string",
            "null"
          ]
        },
        "ref": {
          "description": "The tag the newest snapshot is published under (artifact stores only —\nS3 uses the deployment id as its key prefix). Defaults to\n`workspace-<deployment id>`.",
          "type": [
            "string",
            "null"
          ]
        },
        "snapshot_interval_secs": {
          "description": "Take a snapshot at least this often, in seconds, by recycling the\nreplica: drain, capture, then resume it (`idle_action: retain`) or boot\nits replacement from the result. Unset, a snapshot is taken only when\nthe replica retires for some other reason — a VM that runs for days\nholds days of work that exist nowhere else. Each one costs the drain\nplus the capture as downtime, so at least\n[`MIN_SNAPSHOT_INTERVAL_SECS`].",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint64",
          "minimum": 0
        },
        "store": {
          "description": "Where snapshots go, in one of three forms:\n\n* `s3://bucket[/prefix]` — an S3 bucket, reached with the `aws` CLI and\n  whatever credentials it finds (`APP_LB_DISK_ARCHIVE_ENDPOINT` applies\n  for an S3-compatible store). Snapshots land at\n  `<prefix>/<deployment>/<digest>.tar.gz` with a `latest` pointer.\n* `http(s)://host:port` — a remote `art serve`. Each snapshot is a blob,\n  and [`ref`](Self::artifact_ref) is the tag that names the newest.\n* an absolute path — a local `ART_ROOT`, reached through the `art` CLI.",
          "type": "string"
        }
      },
      "required": [
        "store"
      ]
    }
  }
};
