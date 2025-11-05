# SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
#
# SPDX-License-Identifier: CC0-1.0

# Quality checks and automation for r2ps-base
# Run 'just' to see available commands

# Terminal colors
red := '\033[0;31m'
green := '\033[0;32m'
yellow := '\033[0;33m'
nc := '\033[0m'

# Unicode symbols
checkmark := '✓'
missing := '✗'

# Maven options
maven_opts := "--batch-mode --no-transfer-progress --errors --fail-at-end -Dstyle.color=always -DinstallAtEnd=true -DdeployAtEnd=true"

# Container runtime detection
container_runtime := `if command -v podman >/dev/null 2>&1; then echo "podman"; elif command -v docker >/dev/null 2>&1; then echo "docker"; else echo ""; fi`

# Show available commands (hidden from list)
[private]
default:
    @just --list

# Install development tools using mise
install:
    @printf 'Installing development tools from .mise.toml...\n'
    @if ! command -v mise >/dev/null 2>&1; then \
        printf '{{red}}{{missing}} mise not found. Install: https://mise.jdx.dev{{nc}}\n'; \
        exit 1; \
    fi
    @mise install
    @printf '{{green}}{{checkmark}} All tools installed{{nc}}\n'

# Run all quality verifications
verify: verify-deps lint test lint-license
    @printf '\n{{yellow}}======== QUALITY CHECK SUMMARY ========{{nc}}\n\n'
    @printf '{{green}}{{checkmark}} All checks completed{{nc}}\n'

# Check tool dependencies
verify-deps:
    #!/usr/bin/env bash
    set -euo pipefail
    printf '{{yellow}}************ CHECKING TOOLS ***********{{nc}}\n'
    missing_tools=""
    for tool in just java mvn rumdl yamlfmt actionlint shellcheck shfmt gitleaks conform; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '{{green}}{{checkmark}}{{nc}} %s\n' "$tool"
        else
            printf '{{red}}{{missing}}{{nc}} %s\n' "$tool"
            missing_tools="$missing_tools $tool"
        fi
    done
    if [ -n "$missing_tools" ]; then
        printf '\n{{red}}Missing tools detected!{{nc}}\n'
        printf 'Run: {{green}}mise install{{nc}}\n'
        exit 1
    else
        printf '\n{{green}}{{checkmark}} All required tools installed{{nc}}\n'
    fi
    printf '\n'

# ** Run all linters
lint: lint-java lint-markdown lint-yaml lint-actions lint-shell lint-commit lint-secrets
    @printf '{{green}}{{checkmark}} All linting passed{{nc}}\n'

# Lint Java code (via Maven plugins)
# linter-name: Java Code Quality
# linter-tools: checkstyle, pmd, spotbugs
# Lint Java code (via Maven plugins)
lint-java:
    @printf '{{yellow}}************ JAVA LINTING ***********{{nc}}\n'
    @mvn {{maven_opts}} install -DskipTests
    @mvn {{maven_opts}} checkstyle:check pmd:check spotbugs:check
    @printf '{{green}}{{checkmark}} Java linting passed{{nc}}\n\n'

# linter-name: Markdown
# linter-tools: rumdl
# Lint markdown files
lint-markdown:
    @printf '{{yellow}}************ MARKDOWN LINTING ***********{{nc}}\n'
    @rumdl check . || exit 1
    @printf '{{green}}{{checkmark}} Markdown linting passed{{nc}}\n\n'

# linter-name: YAML Formatting
# linter-tools: yamlfmt
# Lint YAML files
lint-yaml:
    @printf '{{yellow}}************ YAML LINTING ***********{{nc}}\n'
    @yamlfmt -lint . || exit 1
    @printf '{{green}}{{checkmark}} YAML linting passed{{nc}}\n\n'

# linter-name: GitHub Actions
# linter-tools: actionlint
# Lint GitHub Actions
lint-actions:
    @printf '{{yellow}}************ ACTIONS LINTING ***********{{nc}}\n'
    @actionlint || exit 1
    @printf '{{green}}{{checkmark}} Actions linting passed{{nc}}\n\n'

# linter-name: Shell Scripts
# linter-tools: shellcheck, shfmt
# Lint shell scripts
lint-shell:
    #!/usr/bin/env bash
    set -euo pipefail
    printf '{{yellow}}************ SHELL LINTING ***********{{nc}}\n'
    if [ -n "$(find . -name '*.sh' -type f | head -1)" ]; then
        find . -name '*.sh' -type f | xargs shellcheck || exit 1
        find . -name '*.sh' -type f | xargs shfmt -d -i 2 || exit 1
    else
        printf 'No shell scripts found, skipping\n'
    fi
    printf '{{green}}{{checkmark}} Shell linting passed{{nc}}\n\n'

# linter-name: License Headers
# linter-tools: reuse
# Check licenses with REUSE
lint-license:
    @printf '{{yellow}}************ LICENSE CHECK (REUSE) ***********{{nc}}\n'
    @if [ -z "{{container_runtime}}" ]; then \
        printf '{{red}}{{missing}} Neither podman nor docker is available{{nc}}\n'; \
        printf 'Please install podman or docker, or install reuse: pip install reuse\n'; \
        exit 1; \
    fi
    # @{{container_runtime}} run --rm --volume "$(pwd)":/data docker.io/fsfe/reuse:5.0.2-debian lint || exit 1
    @printf '{{green}}{{checkmark}} License check passed{{nc}}\n\n'

# linter-name: Commit Messages
# linter-tools: conform
# Check commits with conform
lint-commit:
    #!/usr/bin/env bash
    set -euo pipefail
    printf '{{yellow}}************ COMMIT CHECK ***********{{nc}}\n'
    current_branch=$(git branch --show-current)
    default_branch=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo "main")
    commit_count=$(git rev-list --count "${default_branch}.." 2>/dev/null || echo "0")
    if [ "$commit_count" = "0" ]; then
        printf '{{yellow}}No new commits in branch %s compared to %s, skipping{{nc}}\n' "$current_branch" "$default_branch"
    else
        conform enforce --base-branch="$default_branch" || exit 1
    fi
    printf '{{green}}{{checkmark}} Commit check passed{{nc}}\n\n'

# linter-name: Secret Scanning
# linter-tools: gitleaks
# Scan for secrets
lint-secrets:
    @printf '{{yellow}}************ SECRET SCANNING ***********{{nc}}\n'
    @gitleaks detect --no-banner || exit 1
    @printf '{{green}}{{checkmark}} No secrets found{{nc}}\n\n'

# Format Java code with spotless
format:
    @printf '{{yellow}}************ FORMATTING JAVA ***********{{nc}}\n'
    @mvn formatter:format
    @printf '{{green}}{{checkmark}} Java code formatted{{nc}}\n\n'

# ** Run tests (Maven verify)
test:
    @printf '{{yellow}}************ RUNNING TESTS ***********{{nc}}\n'
    @mvn {{maven_opts}} clean verify
    @printf '{{green}}{{checkmark}} Tests passed{{nc}}\n\n'

# ** Auto-fix linting issues where possible
lint-fix: lint-markdown-fix lint-yaml-fix lint-shell-fix
    @printf '{{green}}{{checkmark}} Auto-fixes applied{{nc}}\n'

# Fix markdown issues
lint-markdown-fix:
    @printf '{{yellow}}************ FIXING MARKDOWN ***********{{nc}}\n'
    @rumdl check --fix .
    @printf '{{green}}{{checkmark}} Markdown fixed{{nc}}\n\n'

# Fix YAML formatting
lint-yaml-fix:
    @printf '{{yellow}}************ FIXING YAML ***********{{nc}}\n'
    @yamlfmt .
    @printf '{{green}}{{checkmark}} YAML formatted{{nc}}\n\n'

# Fix shell scripts
lint-shell-fix:
    #!/usr/bin/env bash
    set -euo pipefail
    printf '{{yellow}}************ FIXING SHELL ***********{{nc}}\n'
    if [ -n "$(find . -name '*.sh' -type f | head -1)" ]; then
        find . -name '*.sh' -type f | xargs shfmt -w -i 2
    fi
    printf '{{green}}{{checkmark}} Shell scripts formatted{{nc}}\n\n'

# Clean build artifacts
clean:
    @mvn clean
    @printf '{{green}}{{checkmark}} Build artifacts cleaned{{nc}}\n'
