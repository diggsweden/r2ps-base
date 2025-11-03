# Development Guide

This guide outlines core essentials for developing in this project.

## Table of Contents

- [Setup and Configuration](#setup-and-configuration)
  - [IDE Setup](#ide-setup)
  - [Consuming SNAPSHOTS](#consuming-snapshots-from-maven-central)
- [Development Workflow](#development-workflow)
  - [Testing and Verification](#testing-format-and-lint)
  - [Documentation](#documentation)
  - [Pull Request Process](#pull-request-workflow)
- [Release Process](#the-release-workflow)
  - [CI Release](#ci-release-process)
  - [Local Release](#local-release-process)
  - [Troubleshooting](#troubleshooting)

## Setup and Configuration

### IDE Setup

#### VSCode

1. Install [Checkstyle For Java](https://marketplace.visualstudio.com/items?itemName=shengchen.vscode-checkstyle)
2. Open workspace settings - settings.json (for example with Ctrl+Shift+P → Preferences: Workspace Settings (JSON)) and add:

   ```json
   "[java]": {
       "editor.defaultFormatter": "redhat.java",
   },
   "java.format.settings.url": "development/format/eclipse-java-google-style.xml",
   "java.format.settings.profile": "GoogleStyle",
   "editor.formatOnSave": true,
   "java.checkstyle.configuration": "development/lint/google_checks.xml",
   "java.checkstyle.version": "10.26.1"
   ```

#### IntelliJ

1. **Code Style**
   - Settings → `Editor → Code Style → Java`
   - Click gear → `Import Scheme → Eclipse XML Profile`
   - Select `development/format/eclipse-java-google-style.xml`

2. **Checkstyle**
   - Install "CheckStyle-IDEA" plugin
   - Settings → `Tools → Checkstyle`
   - Click the built-in Google Style Check

Note: There might be slight implementation details in how Intellij, VS Code and the maven formatter plugin handles rules.
Noteably, builder patterns are not handled, so if these are formatted in IDE directly, at least maven formatter plugin won't touch them.

### Consuming SNAPSHOTS from Maven Central

Configure your pom.xml with:

```xml
<repositories>
  <repository>
    <name>Central Portal Snapshots</name>
    <id>central-portal-snapshots</id>
    <url>https://central.sonatype.com/repository/maven-snapshots/</url>
    <releases>
      <enabled>false</enabled>
    </releases>
    <snapshots>
      <enabled>true</enabled>
    </snapshots>
  </repository>
</repositories>
```

## Development Workflow

### Testing, Format and Lint

#### Prerequisites

**Important**: Development tools require [mise](https://mise.jdx.dev/) to be installed.

If not added to your shell's automatic initialization (e.g., `.bashrc`, `.zshrc`), run:

```shell
eval "$(mise activate)"
```

#### Quick Start (Recommended)

Format code:

```shell
just format
```

Run all quality checks and tests:

```shell
just verify
```

This will run:

- Code formatter (Google Java Style via Maven formatter plugin)
- All linters (Java, Markdown, YAML, Actions, Shell, Secrets)
- License compliance checks
- Maven tests

Run all quality check:

```shell
just lint
```

Autofix what can be fixed:

```shell
just lint-fix
```

### Documentation

Generate Javadocs:

```shell
mvn javadoc:javadoc
```

View documentation in your browser:

```shell
<browser> target/reports/apidocs/index.html
```

### Pull Request Workflow

When submitting a PR, CI will automatically run several checks. To avoid surprises, run these checks locally first.

#### Prerequisites

Install [mise](https://mise.jdx.dev/) - a tool version manager.
After installation, follow the instructions on the mise install page to activate it in your shell, or restart your shell.

**Note**: If you haven't restarted your shell after installing mise, you may need to manually activate it:

```shell
eval "$(mise activate zsh)"   # for zsh
eval "$(mise activate bash)"  # for bash
eval "$(mise activate fish)"  # for fish
```

#### Running Code Quality Checks Locally

0. List all just runs:

   ```shell
   just
   ```

1. Install all development tools:

   ```shell
   just install-dev-deps
   ```

   Or directly with mise:

   ```shell
   mise install
   ```

2. Run all quality checks:

   ```shell
   just verify
   ```

3. Fix any identified issues (many can be auto-fixed):

   ```shell
   just lint-fix
   ```

4. Update your PR with fixes
5. Verify CI passes in the updated PR

#### Available Just Commands

View all available commands:

```shell
just
```

Common commands:

- `just install` - Install all development tools via mise
- `just format` - Format Java code (Google Java Style)
- `just verify` - Run all quality checks (linting + tests)
- `just verify-deps` - Check if all tools are installed
- `just lint` - Run all linters
- `just lint-java` - Lint Java code (Checkstyle, PMD, SpotBugs)
- `just lint-markdown` - Lint Markdown files
- `just lint-yaml` - Lint YAML files
- `just lint-actions` - Lint GitHub Actions workflows
- `just lint-shell` - Lint shell scripts
- `just lint-commit` - Check commit messages
- `just lint-secrets` - Scan for secrets
- `just lint-license` - Check license compliance
- `just test` - Run Maven tests
- `just lint-fix` - Auto-fix linting issues where possible
- `just clean` - Clean build artifacts

#### Quality Check Details

- **Java Formatting**: Maven formatter plugin with Google Java Style
  - Configuration: `development/format/eclipse-java-google-style.xml`
  - Runs automatically during `mvn verify`
- **Java Linting**: Checkstyle, PMD, and SpotBugs via Maven plugins
  - Checkstyle: Configured to fail only on errors (warnings are reported but don't fail the build)
  - Configuration: `development/lint/google_checks.xml`
  - Runtime version: Checkstyle 10.26.1
- **Markdown Linting**: rumdl for Markdown files
- **YAML Linting**: yamlfmt for YAML files
- **GitHub Actions Linting**: actionlint for workflow files
- **Shell Script Linting**: shellcheck and shfmt for shell scripts
- **License Compliance**: REUSE tool ensures proper copyright information
- **Commit Structure**: Conform checks commit messages for changelog generation
- **Secret Scanning**: gitleaks detects accidentally committed secrets
- **Dependency Analysis**: Scans for vulnerabilities, outdated packages, and license issues
- **OpenSSF Scorecard**: Validates security best practices

#### Handling Failed Checks

If any checks fail in the CI pipeline:

1. Review the CI error logs
2. Run checks locally to reproduce the issues: `just verify`
3. Make necessary fixes in your local environment
4. Try auto-fixes first: `just lint-fix`
5. Update your Pull Request
6. Verify all checks pass in the updated PR

## The Release Workflow

Releases to Maven Central can be done via CI or locally.

### Prerequisites

1. **For CI releases**:
   - Push access to the repository (ability to push tags)
   - For production releases: Your GitHub username in AUTHORIZED_RELEASE_DEVELOPERS list
   - For SNAPSHOT releases: Any contributor with tag push access

2. **For local releases only**:
   - Valid GPG key pair for signing artifacts
   - GPG key uploaded to key servers (e.g., `keyserver.ubuntu.com`)
   - Maven Central credentials in settings.xml

### CI Release Process

1. **For SNAPSHOT releases**:

   ```shell
   # Tag with -SNAPSHOT suffix (use -f to force if tag already exists)
   git tag -sf v0.0.1-SNAPSHOT -m 'v0.0.1-SNAPSHOT'
   # Push the tag to trigger the CI workflow (use -f to force update on remote)
   git push -f origin tag v0.0.1-SNAPSHOT
   ```

   > **NOTE**: Always use the same SNAPSHOT tag version until ready for a production release.

2. **For Production releases**:

   ```shell
   # Tag with the desired version (no SNAPSHOT suffix)
   git tag -s v1.0.0 -m 'v1.0.0'
   # Push the tag to trigger the CI workflow
   git push origin tag v1.0.0
   ```

   > **NOTE**: The tag version will be used in the POM file.

3. **Monitor the workflow** in GitHub Actions to ensure successful completion.

   > **NOTE**: If the workflow fails due to authorization issues, contact the repository administrator to add your GitHub username to the AUTHORIZED_RELEASE_DEVELOPERS list.

### Local Release Process

1. **Configure settings.xml**:
   - Ensure `.mvn/settings.xml` contains your Maven Central username and token
   - Verify credentials are in the correct server section with the proper server ID
   - Make sure your GPG key is available in your environment

2. **Run the deploy command**:

   ```shell
   mvn deploy --settings .mvn/settings.xml -Pcentral-release
   ```

3. **Verify the release** in your Sonatype account or Maven Central.

### Troubleshooting

- For CI failures: Check GitHub Actions logs for detailed error information
- For authorization issues: Verify your GitHub username is in AUTHORIZED_RELEASE_DEVELOPERS
- For GPG problems: Ensure your key is correctly configured in your environment
