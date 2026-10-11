# {{package}}

A Kotodama seiyaku package managed by Musubi. `contracts/{{package}}.ko` declares the
`{{seiyaku}}` seiyaku, and `tests/{{package}}.test.ko` runs its kotoage and view
entrypoints in the IVM. Kotodama compiles the seiyaku to one IVM `.to` artifact.

## Local loop

```sh
musubi check
musubi test
musubi build
```

`musubi build` writes
`target/kotodama/{{namespace}}/{{package}}/dev/{{package}}.to` with its manifest and
public interface. Local commands need no wallet, registry or network.

## Deploy and activate

The seiyaku declares `hajimari` (`始まり`), so a deployed instance rejects every other
call and view until it is activated. For a new Taira account:

```sh
musubi wallet create
musubi wallet fund
musubi wallet namespace <your-domain>
musubi network configure taira --wallet default --contract {{package}} --alias <name::your-domain>
musubi deploy --activate
```

Before calling `increment`, the instance owner or an exact `Increment` role holder
must grant the caller `CanUseContractPermission` with the deployed `contract` address
and `permission: "Increment"`. The deployment receipt supplies the address; activation
alone does not grant this role. Then run:

```sh
musubi call --entrypoint increment --args '{"step":"1"}'
musubi view --contract {{package}} --entrypoint current
```

`int` arguments are canonical decimal strings in JSON, such as `"1"`. Mutable calls
need a funded signer and finite fee authorization. See the
[Musubi tutorial](https://docs.iroha.tech/guide/tutorials/musubi) for the complete
configuration, explicit permission grant, activation and recovery workflow.
