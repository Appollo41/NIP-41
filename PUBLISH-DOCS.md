# Publishing Dokka Docs to GitHub Pages

A runbook to follow when this repo is flipped from private to public. Goal:
public KDoc reference at `https://<owner>.github.io/<repo>/` that auto-rebuilds
on every push to `main`.

Estimated time: ~10 minutes, mostly waiting for the first deploy.

## Prerequisites (verify before starting)

These should already be true from commit `7509e80`. Spot-check:

- [ ] `kmp/nip41/build.gradle.kts` has `id("org.jetbrains.dokka")` and `kotlin { explicitApi() }`.
- [ ] `kmp/gradle.properties` has `org.jetbrains.dokka.experimental.gradle.pluginMode=V2EnabledWithHelpers`.
- [ ] Repo visibility on github.com → Settings → General → "Change repository visibility" is **Public**.
- [ ] Local sanity check passes:
  ```
  cd kmp && ./gradlew :nip41:dokkaGenerate
  open nip41/build/dokka/html/index.html
  ```
  Should show the Dokka HTML index with `IdentityChain`, `deriveIdentityChain`, the verification entry points, `Nip19`, etc. Internal-marked symbols (`Bech32`, `CryptoUtils`, `hkdfSha256`, …) should be absent — that's the explicitApi cleanup working.

## Steps

### 1. Add the workflow

Create `.github/workflows/docs.yml` at the repo root:

```yaml
name: Docs

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: false

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deploy.outputs.page_url }}
    defaults:
      run:
        working-directory: kmp
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: 21
      - uses: gradle/actions/setup-gradle@v4
      - run: ./gradlew :nip41:dokkaGenerate --no-daemon
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: kmp/nip41/build/dokka/html
      - id: deploy
        uses: actions/deploy-pages@v4
```

Commit and push.

### 2. Enable GitHub Pages

On github.com → Settings → Pages:

- Build and deployment → **Source: GitHub Actions**

That's the whole config. No branch selection — the workflow's `deploy-pages` step handles publishing.

### 3. Trigger the first build

Either:
- Push any commit to `main` (the workflow now fires on push), or
- Actions → "Docs" → **Run workflow** → branch `main` → Run.

The Gradle job is ~1–2 minutes on a clean cache; cached runs are ~30 seconds.

### 4. Verify

- **Actions tab**: the "Docs" run is green.
- **Settings → Pages**: a URL appears at the top, typically `https://<owner>.github.io/<repo>/`.
- **Open the URL**. Expect Dokka's HTML index. Click `IdentityChain` to confirm `signWith`, `exportNsec`, `close`, and the redacting `toString` are documented as part of the public API.

### 5. (Optional) Custom domain

Settings → Pages → Custom domain. Add a CNAME or A record at your DNS provider per GitHub's instructions. Tick "Enforce HTTPS" once the cert provisions (a few minutes after the DNS record validates).

## Troubleshooting

| Symptom                                                  | Cause                                          | Fix                                                                  |
| -------------------------------------------------------- | ---------------------------------------------- | -------------------------------------------------------------------- |
| Workflow fails with "Pages is not enabled for this repo" | Step 2 not done                                | Enable Pages and set Source to GitHub Actions                        |
| Workflow fails at `dokkaGenerate`                        | Maven dependency hiccup                        | Re-run the workflow; usually transient                               |
| `dokkaGenerate` warns about Dokka V1                     | `gradle.properties` line missing or commented  | Restore the `dokka.experimental.gradle.pluginMode=V2EnabledWithHelpers` line |
| URL returns 404 after first deploy                       | CDN propagation                                | Wait 2–5 min; hard-refresh                                           |
| New public symbols not in generated docs                 | File's package not in `commonMain` source root | Check the file is under `kmp/nip41/src/commonMain/kotlin/...`        |
| `actions/setup-gradle` warns about cache                 | First-ever run; no cache to restore            | Ignore on first run; subsequent runs reuse it                        |

## After this is set up

- Every push to `main` rebuilds and deploys automatically.
- Manual rebuild: Actions → Docs → Run workflow.
- Local preview before push:
  ```
  cd kmp && ./gradlew :nip41:dokkaGenerate
  open nip41/build/dokka/html/index.html
  ```

## Future phases (out of scope for this runbook)

- **Versioned docs**: when you start cutting releases, the [Dokka versioning plugin](https://kotlinlang.org/docs/dokka-versioning-plugin.html) keeps `/latest/` plus archived versions side-by-side. Not needed for `0.x.y`.
- **JavaDoc.io mirror**: once `maven-publish` is wired (the deferred half of CRIT-2 in [KMP-CODE-REVIEW.md](KMP-CODE-REVIEW.md)) and you publish to Maven Central with a `javadocJar` artifact, [javadoc.io](https://javadoc.io) picks it up automatically. URL convention: `javadoc.io/doc/<group>/<artifact>/latest/`. Complements GitHub Pages — Pages tracks `main`, javadoc.io is per-release.
