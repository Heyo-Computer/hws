# Workflows

A workflow object tells [ci](../ci.md) which repository, ref, workflow files and runner network belong together, and these endpoints create, read, replace and delete them.

Back to the [API reference](overview.md).

ci polls app-lb for workflow objects when `CI_APP_LB_URL` is set, and matches each submit to them by repository URL (`git@github.com:me/app.git` and `https://github.com/me/app` are the same). Several objects may name one repository, and each produces its own runs. All routes are CRUD tier and fleet-wide: a confined caller gets `403`.

## The workflow

`WorkflowView`, from [`workflow.json`](../../app-lb/testdata/wire/workflow.json):

```json
{"id": "build", "repo": "https://github.com/Heyo-Computer/app.git", "ref": "main",
 "path": ".ci/workflows/*.yml", "network": "prod-runners",
 "auth": {"secret": "github", "key": "token"}, "secrets_prefix": "ci/app", "enabled": true}
```

| Field | Meaning |
| --- | --- |
| `id` | Object id. |
| `repo`, `ref` | The repository and ref to run. |
| `path` | Glob of workflow files in the repository. |
| `network` | The runner network to place runs on. |
| `auth` | Secret reference for cloning, never a value. |
| `secrets_prefix` | Prefix of the secrets exposed to runs. |
| `enabled` | Whether ci acts on it. |

## Routes

| Method and path | Crate | Does |
| --- | --- | --- |
| `GET /workflows` | `Client::workflows() -> Vec<WorkflowView>` · `Raw::workflows()` | Every workflow. The body is enveloped as `{"workflows": [...]}` so it can grow a cursor later; the crate unwraps it. |
| `POST /workflows` | `Client::create_workflow(&spec) -> WorkflowView` | Create or replace. Answers `201`. |
| `GET /workflows/:id` | `Client::workflow(id)` · `Raw::workflow(id)` | One workflow. |
| `PUT /workflows/:id` | `Client::replace_workflow(id, &spec) -> WorkflowView` | Replace. Answers `200`. The body's `id`, if present, must match the path. |
| `DELETE /workflows/:id` | `Client::delete_workflow(id) -> ()` | Delete. Answers `204`. |

The write methods take a `Value` for the same reason the deployment writes do: an older client must not drop a newer field on an edit.

| Status | `hws::Error` | When |
| --- | --- | --- |
| `400` | `Api` | The spec failed validation, or the body's id differs from the path's. |
| `403` | `Forbidden` | A confined caller. |
| `404` | `NotFound` | No such workflow. |
| `500` | `Api` | The workflow store could not be written. |
