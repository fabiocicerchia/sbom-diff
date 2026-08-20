# CI Platforms

What it shows: the same dependency-change report on the sixteen CI/CD systems
that aren't GitHub Actions. One file per platform, each one a drop-in.

The composite action is GitHub-specific; the CLI is not. `sbom-diff` is
stdlib-only Python 3.10+, takes two SBOM files, prints markdown, and exits `1`
when an opt-in gate trips. Every file here is that same shape:

```sh
pip install "git+https://github.com/fabiocicerchia/sbom-diff@v1.0.1"
syft -q -o cyclonedx-json=head.json dir:.
syft -q -o cyclonedx-json=base.json dir:/tmp/base
sbom-diff base.json head.json --fail-on major --max-added-transitive 10
```

Pin the tag (`v1.0.1` above), not `main` — a gate that changes underneath you
fails builds you didn't change. There's also an image with the CLI already in
it, `ghcr.io/fabiocicerchia/sbom-diff:1.0.1`, whose entrypoint *is* `sbom-diff`;
the container-native files use it and pass arguments directly.

## Files

| Platform | File | Copy it to |
|---|---|---|
| GitLab CI | [`gitlab-ci.yml`](gitlab-ci.yml) | `.gitlab-ci.yml` |
| CircleCI | [`circleci-config.yml`](circleci-config.yml) | `.circleci/config.yml` |
| Travis CI | [`travis.yml`](travis.yml) | `.travis.yml` |
| Azure DevOps | [`azure-pipelines.yml`](azure-pipelines.yml) | `azure-pipelines.yml` |
| AWS CodePipeline | [`buildspec.yml`](buildspec.yml) | `buildspec.yml` (CodeBuild stage) |
| Devtron | [`devtron-task.sh`](devtron-task.sh) | a Pre-Deployment custom-script task |
| Northflank | [`northflank-job.json`](northflank-job.json) | `northflank create job manual -f …` |
| Spacelift | [`spacelift-config.yml`](spacelift-config.yml) | `.spacelift/config.yml` |
| Jenkins | [`Jenkinsfile`](Jenkinsfile) | `Jenkinsfile` |
| Bitbucket Pipelines | [`bitbucket-pipelines.yml`](bitbucket-pipelines.yml) | `bitbucket-pipelines.yml` |
| Google Cloud Build | [`cloudbuild.yaml`](cloudbuild.yaml) | `cloudbuild.yaml` |
| Tekton | [`tekton.yaml`](tekton.yaml) | `kubectl apply -f` |
| Argo Workflows | [`argo-workflow.yaml`](argo-workflow.yaml) | `argo submit` |
| Harness | [`harness-pipeline.yml`](harness-pipeline.yml) | the pipeline's YAML editor |
| Buildkite | [`buildkite-pipeline.yml`](buildkite-pipeline.yml) | `.buildkite/pipeline.yml` |
| Drone / Woodpecker | [`drone.yml`](drone.yml) | `.drone.yml` / `.woodpecker.yml` |

For GitHub Actions use the action itself — see
[`../github-action/`](../github-action/README.md).

## Two shapes, because there are two questions

The files split by what the platform is *for*:

- **Code CI** (GitLab, CircleCI, Travis, Azure, Jenkins, Bitbucket, Buildkite,
  Drone, Harness) diffs **this branch against its base**: what did this pull
  request do to the dependency tree?
- **Deployment platforms** (Devtron, Northflank, Spacelift, Tekton, Argo,
  CodePipeline) diffs **the live image against the candidate**: what changes if
  this release goes out? Same tool, and the more honest question at that point —
  the image is the artifact, not the lockfile.

## Getting the base side

The base SBOM is the half a one-off scan cannot get, and the half that makes the
numbers mean anything. Each platform names the base differently, and each one
shallow-clones by default, so two things have to be right: **fetch depth** and
**the ref**.

| Platform | Base ref | Full history |
|---|---|---|
| GitLab CI | `$CI_MERGE_REQUEST_DIFF_BASE_SHA` | `GIT_DEPTH: "0"` |
| CircleCI | none — name the branch yourself | `checkout` is already full |
| Travis CI | `$TRAVIS_BRANCH` (the *target* on a PR build) | `git: {depth: false}` |
| Azure DevOps | `$(System.PullRequest.TargetBranch)` (a full `refs/heads/…`) | `fetchDepth: 0` |
| Jenkins | `$CHANGE_TARGET` (Multibranch PR builds) | configure in the branch source |
| Bitbucket | `$BITBUCKET_PR_DESTINATION_BRANCH` | `clone: {depth: full}` |
| Buildkite | `$BUILDKITE_PULL_REQUEST_BASE_BRANCH` | agent clone settings |
| Drone | `$DRONE_TARGET_BRANCH` | `git fetch` in a step |
| Harness | `<+codebase.targetBranch>` | full by default |

`git worktree add` is doing the work in every one of them: it materialises the
base commit next to the checkout without disturbing it, so syft can scan both
trees in the same job.

## Gates

Every threshold is opt-in — a dependency review that fails by default is a
dependency review that gets disabled by default. Drop the flags and the job
reports without ever failing:

`--fail-on {any,major,license}`, `--max-added`, `--max-added-transitive`,
`--fail-on-downgrade`, `--fail-on-license-change`, `--deny-licenses`.

| exit | meaning |
|---|---|
| `0` | no gate tripped (or no gate configured) |
| `1` | a gate tripped |

`--max-added-transitive` needs an SBOM carrying a dependency graph (CycloneDX
`dependencies` / SPDX `relationships`). Without one every component reports as
transitive and the gate fires on any addition at all.

## Where the report goes

The action posts a PR comment and writes a job summary. Neither exists off
GitHub, so the report goes to **stdout as markdown** and each file puts it
somewhere the platform can show it:

- **GitLab** posts it as a merge-request note — one `curl` against the notes
  API. It needs a project access token with `api` scope in `GITLAB_TOKEN`;
  `$CI_JOB_TOKEN` cannot write notes.
- **Buildkite** pipes it into `buildkite-agent annotate`, which renders markdown
  on the build page.
- Everywhere else it is uploaded as a build artifact, alongside both SBOMs so a
  disputed diff can be re-run offline.

`--json` is there when something downstream wants the counts rather than the
prose: it carries both the totals and the rendered markdown.

## Platform notes

**GitLab CI** — `set -o pipefail` before the gate, or `tee` swallows the exit
code and nothing ever fails.

**CircleCI** — exposes no base ref of its own; `BASE_BRANCH` is set explicitly.

**Travis CI** — `TRAVIS_BRANCH` means the target branch on a PR build and the
branch itself on a push build; the file handles both.

**Azure DevOps** — `pr:` triggers only fire for Azure Repos. For a GitHub repo,
build validation is configured on the branch policy instead.

**AWS CodePipeline** — a CodeBuild action in its own stage ahead of Deploy.
Scanning images from ECR needs `ecr:GetAuthorizationToken` and pull permissions
on the CodeBuild service role.

**Devtron** — Pre-Deployment, so a release pulling in a major bump or a denied
license never deploys. Devtron already knows the image tag it built; wire it to
the task's Input Variables rather than restating it.

**Northflank** — a manual job, run as a step in the environment's release
workflow ahead of the deploy step. A failed step stops the rest of the workflow.
The one-line `customCommand` installs both tools at run time; if you run this
often, bake an image with syft and sbom-diff already in it and the command
becomes a single `sbom-diff` call.

**Spacelift** — `before_apply`, the phase where the plan has resolved which
image is about to go live and nothing has been created yet.

**Jenkins** — `agent { docker { … } }` needs the Docker Pipeline plugin. The
`-u root` arg is only there so the syft installer can write to `/usr/local/bin`.

**Bitbucket Pipelines** — `clone: {depth: full}` matters: the default shallow
clone cannot reach the destination branch.

**Google Cloud Build** — both tools ship as images with the right entrypoint, so
no step needs a shell: syft writes each SBOM to a file, sbom-diff reads the pair.

**Tekton** — three steps in one Task sharing a `reports` workspace. Reference it
from a Pipeline ahead of whatever deploys.

**Argo Workflows** — the DAG is the gate: `deploy` depends on `diff`, so a
tripped gate leaves it unrun. The two syft scans run in parallel.

**Harness** — a `Run` step in a CI stage. `image:` is optional on Harness Cloud;
on Kubernetes build infrastructure the step needs a `connectorRef`.

**Buildkite** — Buildkite interpolates `$VAR` at pipeline *upload* time, so
anything the shell must expand at *run* time is written `$$VAR`.

**Drone / Woodpecker** — steps share the workspace volume and nothing else, so
every path is workspace-relative. The head scan runs before the base worktree
exists, so it never sees `.base/` in its own tree.
