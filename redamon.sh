#!/usr/bin/env bash
# =============================================================================
# RedAmon CLI - Simplified installation, update, and lifecycle management
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_FILE="$SCRIPT_DIR/VERSION"
GVM_FLAG_FILE="$SCRIPT_DIR/.gvm-enabled"

# Service lists
CORE_SERVICES="postgres neo4j recon-orchestrator kali-sandbox agent webapp"
TOOL_IMAGES="redamon-recon:latest redamon-vuln-scanner:latest redamon-github-hunter:latest redamon-trufflehog:latest"
DEV_COMPOSE="-f docker-compose.yml -f docker-compose.dev.yml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

print_banner() {
    echo -e "${RED}${BOLD}"
    echo "  ____          _    _                         "
    echo " |  _ \\ ___  __| |  / \\   _ __ ___   ___  _ __"
    echo " | |_) / _ \\/ _\` | / _ \\ | '_ \` _ \\ / _ \\| '_ \\ "
    echo " |  _ <  __/ (_| |/ ___ \\| | | | | | (_) | | | |"
    echo " |_| \\_\\___|\\__,_/_/   \\_\\_| |_| |_|\\___/|_| |_|"
    echo -e "${NC}"
}

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }

get_version() {
    if [[ -f "$VERSION_FILE" ]]; then
        cat "$VERSION_FILE" | tr -d '[:space:]'
    else
        echo "unknown"
    fi
}

is_gvm_enabled() {
    [[ -f "$GVM_FLAG_FILE" ]]
}

check_prerequisites() {
    local missing=0

    if ! command -v docker &>/dev/null; then
        error "Docker is not installed. See: https://docs.docker.com/get-docker/"
        missing=1
    fi

    if ! docker compose version &>/dev/null; then
        error "Docker Compose v2 is not installed. See: https://docs.docker.com/compose/install/"
        missing=1
    fi

    if ! command -v git &>/dev/null; then
        error "Git is not installed."
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        exit 1
    fi
}

export_version() {
    export REDAMON_VERSION
    REDAMON_VERSION="$(get_version)"
}

remove_redamon_images() {
    # Remove locally-built redamon images
    docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep '^redamon-' \
        | xargs -r docker rmi 2>/dev/null || true

    # Remove GVM / Greenbone images
    docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep 'registry.community.greenbone.net' \
        | xargs -r docker rmi 2>/dev/null || true

    # Remove ProjectDiscovery + recon tool images (pulled at runtime by entrypoint)
    local runtime_images=(
        "projectdiscovery/naabu"
        "projectdiscovery/httpx"
        "projectdiscovery/katana"
        "projectdiscovery/nuclei"
        "projectdiscovery/subfinder"
        "projectdiscovery/dnsx"
        "projectdiscovery/uncover"
        "sxcurity/gau"
        "caffix/amass"
        "frost19k/puredns"
        "jauderho/hakrawler"
        "trufflesecurity/trufflehog"
    )
    for img in "${runtime_images[@]}"; do
        docker rmi "$img" 2>/dev/null || true
    done
}

pull_gvm_images() {
    # GVM images are large (~250MB each) and can fail with "unexpected EOF"
    # due to a known Docker+Go 1.24 bug (moby/moby#49513) and Greenbone
    # registry instability. Pull individually with retries.
    local max_retries=5
    local gvm_services
    gvm_services=$(docker compose config --services 2>/dev/null | grep '^gvm-')

    if [[ -z "$gvm_services" ]]; then
        return 0
    fi

    info "Pulling GVM images (with retry)..."
    local failed=()
    for svc in $gvm_services; do
        local attempt=1
        while [[ $attempt -le $max_retries ]]; do
            if docker compose pull "$svc" 2>/dev/null; then
                break
            fi
            if [[ $attempt -lt $max_retries ]]; then
                warn "Pull failed for $svc (attempt $attempt/$max_retries), retrying..."
                sleep 5
            fi
            ((attempt++))
        done
        if [[ $attempt -gt $max_retries ]]; then
            failed+=("$svc")
        fi
    done

    # Also pull gvmd separately (no gvm- prefix)
    local attempt=1
    while [[ $attempt -le $max_retries ]]; do
        if docker compose pull gvmd 2>/dev/null; then
            break
        fi
        if [[ $attempt -lt $max_retries ]]; then
            warn "Pull failed for gvmd (attempt $attempt/$max_retries), retrying..."
            sleep 3
        fi
        ((attempt++))
    done
    if [[ $attempt -gt $max_retries ]]; then
        failed+=(gvmd)
    fi

    if [[ ${#failed[@]} -gt 0 ]]; then
        error "Failed to pull after $max_retries attempts: ${failed[*]}"
        echo ""
        echo -e "  ${YELLOW}This is often caused by a Docker+Go 1.24 bug (moby/moby#49513).${NC}"
        echo -e "  ${YELLOW}Try: echo '{\"max-concurrent-downloads\":1}' | sudo tee /etc/docker/daemon.json${NC}"
        echo -e "  ${YELLOW}Then: sudo systemctl restart docker && ./redamon.sh up${NC}"
        exit 1
    fi
    success "All GVM images pulled successfully."
}

# ---------------------------------------------------------------------------
# Knowledge Base helpers
# ---------------------------------------------------------------------------

KB_CONFIG_YAML="$SCRIPT_DIR/knowledge_base/kb_config.yaml"

# Read a value from kb_config.yaml. Dotted paths are supported for nested
# keys. Falls back to $2 if the file, key, or python is unavailable.
#   $1: dotted key path (e.g. "runtime.mode" or "KB_ENABLED")
#   $2: fallback value
_kb_yaml_get() {
    local key="$1"
    local fallback="$2"
    python3 -c "
import sys, yaml
try:
    with open('$KB_CONFIG_YAML') as f:
        cfg = yaml.safe_load(f) or {}
    value = cfg
    for k in '$key'.split('.'):
        value = value[k]
    if isinstance(value, bool):
        print('true' if value else 'false')
    else:
        print(value)
except Exception:
    print('$fallback')
" 2>/dev/null || echo "$fallback"
}

# Feature gate mirroring is_gvm_enabled(). Reads KB_ENABLED from
# knowledge_base/kb_config.yaml. Env var override wins if explicitly set:
# KB_ENABLED=false ./redamon.sh install
is_kb_enabled() {
    # Env var override takes precedence
    if [[ -n "${KB_ENABLED:-}" ]]; then
        [[ "${KB_ENABLED}" != "false" ]]
        return
    fi
    # Otherwise read from YAML (default: true)
    local value
    value=$(_kb_yaml_get "KB_ENABLED" "true")
    [[ "$value" != "false" ]]
}

# Export KB-related env vars derived from kb_config.yaml so downstream
# processes (docker compose, make) see consistent values. Called from
# cmd_install, cmd_up, and the cmd_kb_* functions before shelling out.
_kb_export_env() {
    if [[ -z "${KB_ENABLED:-}" ]]; then
        export KB_ENABLED
        KB_ENABLED=$(_kb_yaml_get "KB_ENABLED" "true")
    fi
}

# Wait for the Neo4j container to become healthy. Starts it if not running.
# Returns 0 on success, 1 on timeout.
_kb_wait_neo4j() {
    if ! docker ps --format '{{.Names}}' | grep -q '^redamon-neo4j$'; then
        info "Neo4j not running — starting it..."
        docker compose up -d neo4j
    fi

    info "Waiting for Neo4j to become healthy..."
    local waited=0
    local max_wait=60
    while [[ $waited -lt $max_wait ]]; do
        local health
        health=$(docker inspect --format='{{.State.Health.Status}}' \
                   redamon-neo4j 2>/dev/null || echo "unknown")
        if [[ "$health" == "healthy" ]]; then
            success "Neo4j is healthy"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done

    error "Neo4j did not become healthy within ${max_wait}s"
    error "Check: docker logs redamon-neo4j"
    return 1
}

# Internal: run `make kb-build-<profile>` with Neo4j health check first.
# Fails gracefully — callers decide whether to treat failure as fatal.
_kb_bootstrap() {
    local profile="${1:-lite}"
    _kb_export_env
    _kb_wait_neo4j || return 1
    info "Bootstrapping Knowledge Base (profile=${profile})..."
    make "kb-build-${profile}"
}

# Status helpers: read KB and Tavily state directly from disk/env without
# requiring Python deps, running containers, or Neo4j connections. These
# should always succeed (or return a safe fallback) so `./redamon.sh status`
# works in any state.

# Count FAISS vectors by reading chunk_ids.json directly. No Python dep
# required — uses python3's stdlib json module, which is always present.
# Returns "0" if the file is missing or unreadable.
_kb_get_faiss_count() {
    local chunk_ids="$SCRIPT_DIR/knowledge_base/data/chunk_ids.json"
    if [[ ! -f "$chunk_ids" ]]; then
        echo "0"
        return
    fi
    python3 -c "
import json, sys
try:
    with open('$chunk_ids') as f:
        data = json.load(f)
    print(len(data) if isinstance(data, list) else 0)
except Exception:
    print('0')
" 2>/dev/null || echo "0"
}

# Count Neo4j KBChunk nodes via cypher-shell inside the neo4j container.
# Returns "0" if the container isn't running, "unknown" if the query fails.
_kb_get_neo4j_count() {
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-neo4j$'; then
        echo "0"
        return
    fi
    local pass="${NEO4J_PASSWORD:-changeme123}"
    local user="${NEO4J_USER:-neo4j}"
    local count
    count=$(docker exec redamon-neo4j cypher-shell \
        -u "$user" -p "$pass" --format plain \
        "MATCH (c:KBChunk) RETURN count(c) AS total" 2>/dev/null \
        | tail -n 1 | tr -d '[:space:]"' || true)
    # Validate it's a non-negative integer; fall back to unknown otherwise
    if [[ "$count" =~ ^[0-9]+$ ]]; then
        echo "$count"
    else
        echo "unknown"
    fi
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_install() {
    local gvm_mode="false"
    if [[ "${1:-}" == "--gvm" ]]; then
        gvm_mode="true"
    fi

    print_banner
    check_prerequisites

    local version
    version="$(get_version)"
    info "Installing RedAmon v${version}..."
    if [[ "$gvm_mode" == "true" ]]; then
        info "Mode: Full stack (with GVM/OpenVAS)"
        touch "$GVM_FLAG_FILE"
    else
        info "Mode: Core services (without GVM/OpenVAS)"
        rm -f "$GVM_FLAG_FILE"
    fi
    echo ""

    # Export version for docker build arg
    export_version

    # Build all images (tools + core services)
    info "Building all images (this may take a while on first run)..."
    docker compose --profile tools build

    # Pull GVM images with retry (large images, unreliable registry)
    if [[ "$gvm_mode" == "true" ]]; then
        pull_gvm_images
    fi

    # Start services (force-recreate ensures compose changes like command: are applied)
    info "Starting services..."
    if [[ "$gvm_mode" == "true" ]]; then
        docker compose up -d --force-recreate
    else
        # shellcheck disable=SC2086
        docker compose up -d --force-recreate $CORE_SERVICES
    fi

    # Bootstrap the Knowledge Base if enabled (reads KB_ENABLED from kb_config.yaml).
    # Install always runs a fresh bootstrap — first-time setup populates FAISS +
    # Neo4j from committed caches. Graceful failure: if bootstrap fails
    # (network, missing deps, etc.) the agent still starts with an empty KB
    # and the user gets a clear retry command.
    if is_kb_enabled; then
        echo ""
        info "Bootstrapping Knowledge Base (lite profile)..."
        if _kb_bootstrap lite; then
            success "Knowledge Base ready"
        else
            warn "KB bootstrap failed — agent will start with an empty KB"
            warn "Retry with: ./redamon.sh kb build lite"
        fi
    else
        info "KB_ENABLED=false — skipping Knowledge Base bootstrap"
    fi

    echo ""
    success "RedAmon v${version} installed and running!"
    echo ""
    echo -e "  ${CYAN}Webapp:${NC}  http://localhost:3000"
    echo -e "  ${CYAN}Status:${NC}  ./redamon.sh status"
    echo ""
    echo -e "  ${YELLOW}If RedAmon is useful to you, a GitHub star helps others find the project:${NC}"
    echo -e "  ${CYAN}https://github.com/samugit83/redamon${NC}"
    echo ""
    if [[ "$gvm_mode" == "true" ]]; then
        warn "GVM/OpenVAS feed sync takes ~30 minutes on first run."
        echo -e "  ${CYAN}GVM credentials:${NC} admin / admin"
    fi
}

cmd_update() {
    print_banner
    check_prerequisites

    local old_version
    old_version="$(get_version)"
    info "Current version: v${old_version}"
    info "Checking for updates..."
    echo ""

    # Save current HEAD
    local old_head new_head
    old_head="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"

    # Pull latest (try upstream tracking branch first, then origin/master)
    if ! git -C "$SCRIPT_DIR" pull --ff-only 2>/dev/null; then
        if ! git -C "$SCRIPT_DIR" pull --ff-only origin master 2>/dev/null; then
            error "Could not pull updates. You may have local changes."
            echo ""
            echo "  Try one of:"
            echo "    git stash && ./redamon.sh update && git stash pop"
            echo "    git commit -am 'local changes' && ./redamon.sh update"
            exit 1
        fi
    fi

    new_head="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"

    if [[ "$old_head" == "$new_head" ]]; then
        success "Already up to date (v$(get_version))."
        return
    fi

    local new_version
    new_version="$(get_version)"
    info "Updating v${old_version} -> v${new_version}"
    echo ""

    # Detect what changed
    local changed_files
    changed_files="$(git -C "$SCRIPT_DIR" diff --name-only "$old_head" "$new_head")"

    # Map changed paths to services
    local rebuild_core=()
    local rebuild_tools=()
    local rebuild_all=false

    if echo "$changed_files" | grep -q "^docker-compose\.yml$"; then
        rebuild_all=true
    fi

    # Track services that need restart only (volume-mounted source code changes)
    local restart_only=()

    if [[ "$rebuild_all" == "true" ]]; then
        info "docker-compose.yml changed -- rebuilding all images"
        rebuild_core=(recon-orchestrator kali-sandbox agent webapp)
        rebuild_tools=(recon vuln-scanner github-secret-hunter trufflehog-scanner)
    else
        # webapp: always needs rebuild (no volume mount in production)
        if echo "$changed_files" | grep -q "^webapp/"; then
            rebuild_core+=(webapp)
        fi

        # recon-orchestrator: rebuild only if Dockerfile/requirements changed, else restart
        if echo "$changed_files" | grep -q "^recon_orchestrator/\(Dockerfile\|requirements\)"; then
            rebuild_core+=(recon-orchestrator)
        elif echo "$changed_files" | grep -q "^recon_orchestrator/"; then
            restart_only+=(recon-orchestrator)
        fi

        # kali-sandbox: rebuild only if Dockerfile/entrypoint changed, else restart
        if echo "$changed_files" | grep -q "^mcp/kali-sandbox/\(Dockerfile\|entrypoint\)"; then
            rebuild_core+=(kali-sandbox)
        elif echo "$changed_files" | grep -q "^mcp/"; then
            restart_only+=(kali-sandbox)
        fi

        # agent: rebuild only if Dockerfile/requirements changed, else restart.
        # The agent build context is the project root (./), and the image bakes in
        # both knowledge_base/ and graph_db/ as sibling packages, so changes to those
        # directories also require a rebuild.
        if echo "$changed_files" | grep -q "^agentic/\(Dockerfile\|requirements\)"; then
            rebuild_core+=(agent)
        elif echo "$changed_files" | grep -qE "^(knowledge_base|graph_db)/"; then
            rebuild_core+=(agent)
        elif echo "$changed_files" | grep -q "^agentic/"; then
            restart_only+=(agent)
        fi

        # Tool-profile images (build-only, not running containers)
        if echo "$changed_files" | grep -q "^recon/"; then
            rebuild_tools+=(recon)
        fi
        if echo "$changed_files" | grep -q "^gvm_scan/"; then
            rebuild_tools+=(vuln-scanner)
        fi
        if echo "$changed_files" | grep -q "^github_secret_hunt/"; then
            rebuild_tools+=(github-secret-hunter)
        fi
        if echo "$changed_files" | grep -q "^trufflehog_scan/"; then
            rebuild_tools+=(trufflehog-scanner)
        fi
    fi

    # Export version for build arg
    export_version

    # Rebuild tool-profile images
    if [[ ${#rebuild_tools[@]} -gt 0 ]]; then
        info "Rebuilding tool images: ${rebuild_tools[*]}"
        docker compose --profile tools build "${rebuild_tools[@]}"
    fi

    # Rebuild core service images
    if [[ ${#rebuild_core[@]} -gt 0 ]]; then
        info "Rebuilding service images: ${rebuild_core[*]}"
        docker compose build "${rebuild_core[@]}"
    fi

    # Clean up dangling images left by rebuilds
    if [[ ${#rebuild_core[@]} -gt 0 || ${#rebuild_tools[@]} -gt 0 ]]; then
        docker image prune -f >/dev/null 2>&1 || true
    fi

    # Restart rebuilt core services (tool images are build-only, not running)
    if [[ ${#rebuild_core[@]} -gt 0 ]]; then
        info "Restarting rebuilt services..."
        for svc in "${rebuild_core[@]}"; do
            docker compose up -d --no-deps "$svc"
        done
    fi

    # Recreate GVM containers when docker-compose.yml changed (picks up command/image/volume changes)
    if [[ "$rebuild_all" == "true" ]] && is_gvm_enabled; then
        info "Recreating GVM containers to apply compose changes..."
        pull_gvm_images
        docker compose up -d --force-recreate gvm-redis gvm-postgres gvmd gvm-ospd
    fi

    # Restart services with volume-mounted code changes (no rebuild needed)
    if [[ ${#restart_only[@]} -gt 0 ]]; then
        info "Restarting services for code changes: ${restart_only[*]}"
        docker compose restart "${restart_only[@]}"
    fi

    echo ""
    success "Updated to v${new_version}!"
    if [[ ${#rebuild_core[@]} -gt 0 || ${#rebuild_tools[@]} -gt 0 ]]; then
        local rebuilt_list="${rebuild_core[*]:+${rebuild_core[*]} }${rebuild_tools[*]}"
        echo -e "  ${CYAN}Rebuilt:${NC}  ${rebuilt_list}"
    fi
    if [[ ${#restart_only[@]} -gt 0 ]]; then
        echo -e "  ${CYAN}Restarted:${NC} ${restart_only[*]}"
    fi
    if [[ ${#rebuild_core[@]} -eq 0 && ${#rebuild_tools[@]} -eq 0 && ${#restart_only[@]} -eq 0 ]]; then
        info "No container images or source code needed updating."
    fi
    echo -e "  ${CYAN}Webapp:${NC}  http://localhost:3000"
}

ensure_tool_images() {
    local missing=false
    for img in $TOOL_IMAGES; do
        if ! docker image inspect "$img" &>/dev/null; then
            missing=true
            break
        fi
    done
    if [[ "$missing" == "true" ]]; then
        info "Tool images not found, building them (first time only)..."
        export_version
        docker compose --profile tools build
        success "Tool images built."
    fi
}

cmd_up_dev() {
    local gvm_flag="false"
    shift || true  # consume 'dev'
    if [[ "${1:-}" == "--gvm" ]]; then
        gvm_flag="true"
    fi

    ensure_tool_images

    info "Starting RedAmon in DEV mode (GVM: ${gvm_flag})..."

    if [[ "$gvm_flag" == "true" ]]; then
        pull_gvm_images
        # shellcheck disable=SC2086
        docker compose $DEV_COMPOSE up -d
    else
        # shellcheck disable=SC2086
        docker compose $DEV_COMPOSE up -d $CORE_SERVICES
    fi

    # Refresh the Knowledge Base if enabled (behavior B — always run ingest,
    # trust manifest dedup). Same rationale as cmd_up. Dev mode still benefits
    # from fresh KB on restart.
    if is_kb_enabled; then
        echo ""
        info "Refreshing Knowledge Base (lite profile)..."
        if _kb_bootstrap lite; then
            success "Knowledge Base ready"
        else
            warn "KB refresh failed — agent will start with the existing KB state"
            warn "Retry with: ./redamon.sh kb build lite"
        fi
    fi

    echo ""
    success "RedAmon DEV is running at http://localhost:3000 (hot-reload enabled)"
}

cmd_up() {
    local gvm_mode="false"
    if is_gvm_enabled; then
        gvm_mode="true"
    fi

    info "Starting RedAmon (GVM: ${gvm_mode})..."

    # Pull GVM images with retry (large images, unreliable registry)
    if [[ "$gvm_mode" == "true" ]]; then
        pull_gvm_images
    fi

    if [[ "$gvm_mode" == "true" ]]; then
        docker compose up -d --force-recreate
    else
        # shellcheck disable=SC2086
        docker compose up -d --force-recreate $CORE_SERVICES
    fi

    # Refresh the Knowledge Base if enabled. Behavior B: always run the ingest
    # pipeline on up. The two-layer dedup (file hashes + manifest) skips
    # unchanged work, and NVD uses the `since` mechanism for incremental
    # updates — so a routine restart is ~20-30s even though it touches the
    # network. First-ever up is ~2-3 min (full NVD fetch + embedding).
    # Fresh-clone scenario: no FAISS on disk → full bootstrap.
    if is_kb_enabled; then
        echo ""
        info "Refreshing Knowledge Base (lite profile)..."
        if _kb_bootstrap lite; then
            success "Knowledge Base ready"
        else
            warn "KB refresh failed — agent will start with the existing KB state"
            warn "Retry with: ./redamon.sh kb build lite"
        fi
    fi

    echo ""
    success "RedAmon is running at http://localhost:3000"
}

cmd_down() {
    info "Stopping RedAmon..."
    docker compose down
    success "All services stopped. Volumes and images preserved."
}

cmd_clean() {
    warn "This will remove all RedAmon containers and images."
    warn "Your data (databases, reports, scan results) will be preserved in Docker volumes."
    echo ""
    read -rp "Continue? [y/N] " confirm
    if [[ "${confirm,,}" != "y" ]]; then
        info "Cancelled."
        return
    fi

    info "Stopping containers..."
    docker compose --profile tools down

    info "Removing RedAmon images..."
    remove_redamon_images
    docker image prune -f >/dev/null 2>&1 || true

    success "All RedAmon containers and images removed. Volumes preserved."
    echo ""
    info "To reinstall: ./redamon.sh install"
}

cmd_purge() {
    echo ""
    warn "This will PERMANENTLY DELETE:"
    warn "  - All RedAmon containers and images"
    warn "  - ALL DATA: PostgreSQL, Neo4j, GVM feeds, reports, scan results"
    warn "  - Host-side KB index state (FAISS index, manifest, last-ingest marker)"
    warn "  - KB dedup state (.manifest.json, .file_hashes.json)"
    warn "  - Downloaded source files under knowledge_base/data/cache are PRESERVED"
    echo ""
    echo -e "${RED}${BOLD}This action cannot be undone.${NC}"
    echo ""
    read -rp "Type 'yes' to confirm: " confirm
    if [[ "$confirm" != "yes" ]]; then
        info "Cancelled."
        return
    fi

    info "Stopping containers and removing volumes..."
    docker compose --profile tools down --volumes --remove-orphans

    info "Removing RedAmon images..."
    remove_redamon_images
    docker image prune -f >/dev/null 2>&1 || true

    # Host-side KB state files that must be wiped in lockstep with the
    # Neo4j volume. Leaving these behind after a purge causes a
    # split-brain on reinstall: Neo4j is empty but FAISS still has
    # stale vectors, and the dedup layers still think every chunk is
    # already ingested, so the bootstrap build becomes a no-op and
    # Neo4j stays empty.
    #
    # The on-disk content under knowledge_base/data/cache (tarballs,
    # CSVs, YAML templates, markdown) is deliberately preserved —
    # those are ~30+ MB of downloaded source files that don't need to
    # be re-fetched from GitHub/GitLab/NVD on every reinstall. What we
    # DO wipe are the dedup sidecars that model "what Neo4j already
    # has":
    #   - .manifest.json          (chunk-level hash dedup, Layer 2)
    #   - .file_hashes.json       (file-level hash dedup, Layer 1)
    # These live inside data/cache but are state, not content.
    info "Removing host-side KB index state..."
    rm -f \
        "$SCRIPT_DIR/knowledge_base/data/index.faiss" \
        "$SCRIPT_DIR/knowledge_base/data/chunk_ids.json" \
        "$SCRIPT_DIR/knowledge_base/data/index.faiss.manifest.json" \
        "$SCRIPT_DIR/knowledge_base/data/.last_ingest"

    info "Removing host-side KB dedup state (manifest + file hashes)..."
    rm -f "$SCRIPT_DIR/knowledge_base/data/cache/.manifest.json"
    # Wipe every per-source .file_hashes.json without touching the
    # downloaded content alongside it. -print is for operator feedback.
    if [[ -d "$SCRIPT_DIR/knowledge_base/data/cache" ]]; then
        find "$SCRIPT_DIR/knowledge_base/data/cache" \
            -type f -name '.file_hashes.json' -print -delete \
            2>/dev/null || true
    fi

    rm -f "$GVM_FLAG_FILE"
    success "Full cleanup complete. All RedAmon data and images have been removed."
    echo ""
    info "To reinstall: ./redamon.sh install"
}

cmd_status() {
    local version
    version="$(get_version)"

    print_banner
    echo -e "  ${CYAN}Version:${NC}       v${version}"

    # GVM feature gate
    if is_gvm_enabled; then
        echo -e "  ${CYAN}GVM_ENABLED:${NC}   ${GREEN}true${NC}"
    else
        echo -e "  ${CYAN}GVM_ENABLED:${NC}   false"
    fi

    # KB feature gate (from kb_config.yaml / env var)
    if is_kb_enabled; then
        echo -e "  ${CYAN}KB_ENABLED:${NC}    ${GREEN}true${NC}"
    else
        echo -e "  ${CYAN}KB_ENABLED:${NC}    false"
    fi

    # KB data state — always shown, independent of KB_ENABLED
    local faiss_count neo4j_count kb_state
    faiss_count=$(_kb_get_faiss_count)
    neo4j_count=$(_kb_get_neo4j_count)

    if [[ "$faiss_count" == "0" && "$neo4j_count" == "0" ]]; then
        kb_state="${YELLOW}empty${NC}"
    elif [[ "$faiss_count" == "unknown" || "$neo4j_count" == "unknown" ]]; then
        kb_state="${YELLOW}unknown${NC}"
    elif [[ "$faiss_count" == "0" || "$neo4j_count" == "0" ]]; then
        kb_state="${YELLOW}partial${NC}"
    else
        kb_state="${GREEN}populated${NC}"
    fi
    echo -e "  ${CYAN}KB:${NC}            ${kb_state} (FAISS: ${faiss_count} vectors; NEO4J: ${neo4j_count} chunks)"

    echo ""

    # Container list — filter to redamon containers only. Keeps the header
    # row and any container whose name starts with "redamon-".
    docker compose ps | grep -E '^(NAME|redamon-)' || {
        # grep returns non-zero if no lines match (no containers running).
        # Fall back to plain ps so the user still sees the "no services" message.
        docker compose ps
    }
}

# ---------------------------------------------------------------------------
# Knowledge Base commands
# ---------------------------------------------------------------------------

cmd_kb_build() {
    local profile="${1:-lite}"
    case "$profile" in
        lite|standard|full) ;;
        *)
            error "Unknown KB profile: $profile"
            echo "Usage: ./redamon.sh kb build [lite|standard|full]"
            exit 1
            ;;
    esac

    print_banner
    info "Building Knowledge Base (profile=${profile})"
    echo ""

    _kb_export_env
    _kb_wait_neo4j || exit 1

    info "Running ingestion pipeline..."
    if ! make "kb-build-${profile}"; then
        error "KB build failed"
        exit 1
    fi

    echo ""
    success "Knowledge Base built successfully"
    make kb-stats
}

cmd_kb_update() {
    local source="${1:-}"

    print_banner
    _kb_export_env
    _kb_wait_neo4j || exit 1

    if [[ -n "$source" ]]; then
        case "$source" in
            nvd|exploitdb|nuclei|gtfobins|lolbas|owasp|tools) ;;
            *)
                error "Unknown KB source: $source"
                echo "Valid sources: nvd, exploitdb, nuclei, gtfobins, lolbas, owasp, tools"
                exit 1
                ;;
        esac
        info "Updating KB source: ${source}"
        if ! make "kb-update-${source}"; then
            error "KB update failed for ${source}"
            exit 1
        fi
    else
        info "Updating all KB sources (incremental)"
        local failed=()
        for src in nvd exploitdb nuclei gtfobins lolbas owasp tools; do
            echo ""
            info "→ ${src}"
            make "kb-update-${src}" || failed+=("$src")
        done
        if [[ ${#failed[@]} -gt 0 ]]; then
            echo ""
            warn "Some sources failed to update: ${failed[*]}"
        fi
    fi

    echo ""
    success "Knowledge Base update complete"
    make kb-stats
}

cmd_kb_rebuild() {
    local profile="${1:-standard}"
    case "$profile" in
        lite|standard|full) ;;
        *)
            error "Invalid profile '$profile'. Use lite, standard, or full."
            echo "Usage: ./redamon.sh kb rebuild [lite|standard|full]"
            exit 1
            ;;
    esac

    print_banner
    warn "This will WIPE and rebuild the entire Knowledge Base."
    info "Profile: $profile"
    echo ""

    _kb_export_env
    _kb_wait_neo4j || exit 1

    info "Rebuilding Knowledge Base from scratch..."
    if ! make "kb-rebuild-${profile}"; then
        error "KB rebuild failed"
        exit 1
    fi

    echo ""
    success "Knowledge Base rebuilt"
    make kb-stats
}

cmd_kb_stats() {
    _kb_export_env
    _kb_wait_neo4j || exit 1
    make kb-stats
}

cmd_kb_help() {
    echo -e "${BOLD}Usage:${NC} ./redamon.sh kb <command> [args]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}build [profile]${NC}    Build KB — profile: lite (default) | standard | full"
    echo -e "  ${GREEN}update [source]${NC}    Update KB — all sources, or one: nvd|exploitdb|nuclei|gtfobins|lolbas|owasp|tools"
    echo -e "  ${GREEN}rebuild${NC}            Wipe and rebuild (standard profile)"
    echo -e "  ${GREEN}stats${NC}              Show FAISS + Neo4j chunk counts"
    echo -e "  ${GREEN}help${NC}               Show this help"
    echo ""
    echo -e "${BOLD}Profiles:${NC}"
    echo "  lite      tool_docs + metasploit + gtfobins + lolbas + owasp + exploitdb + NVD (90 days)"
    echo "  standard  same sources as lite + NVD (2 years)"
    echo "  full      standard + Nuclei (requires redamon-kali container running)"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./redamon.sh kb build             # Build lite KB (default)"
    echo "  ./redamon.sh kb build standard    # Build with 2 years of NVD"
    echo "  ./redamon.sh kb rebuild           # Wipe + rebuild standard (default)"
    echo "  ./redamon.sh kb rebuild lite      # Wipe + rebuild lite profile"
    echo "  ./redamon.sh kb rebuild full      # Wipe + rebuild full profile (incl. nuclei)"
    echo "  ./redamon.sh kb update nvd        # Incremental NVD refresh"
    echo "  ./redamon.sh kb update            # Update all sources"
    echo "  ./redamon.sh kb stats             # See what's in the KB"
    echo ""
}

cmd_help() {
    print_banner
    echo -e "${BOLD}Usage:${NC} ./redamon.sh <command> [options]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}install${NC}          Build and start RedAmon (without GVM)"
    echo -e "  ${GREEN}install --gvm${NC}    Build and start RedAmon (with GVM/OpenVAS)"
    echo -e "  ${GREEN}update${NC}           Pull latest version and smart-rebuild changed services"
    echo -e "  ${GREEN}up${NC}               Start services"
    echo -e "  ${GREEN}up dev${NC}           Start in dev mode (hot-reload, auto-builds tool images)"
    echo -e "  ${GREEN}up dev --gvm${NC}     Start in dev mode with GVM/OpenVAS"
    echo -e "  ${GREEN}down${NC}             Stop services (preserves data)"
    echo -e "  ${GREEN}clean${NC}            Remove containers and images (keeps data)"
    echo -e "  ${GREEN}purge${NC}            Remove everything including all data"
    echo -e "  ${GREEN}status${NC}           Show running services, version, GVM, and KB state"
    echo -e "  ${GREEN}kb <command>${NC}     Knowledge Base management (build/update/rebuild/stats)"
    echo -e "  ${GREEN}help${NC}             Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./redamon.sh install          # First-time setup (no GVM)"
    echo "  ./redamon.sh install --gvm    # First-time setup (full stack)"
    echo "  ./redamon.sh update           # Update to latest version"
    echo "  ./redamon.sh up               # Start after reboot"
    echo "  ./redamon.sh up dev           # Dev mode with hot-reload"
    echo "  ./redamon.sh up dev --gvm     # Dev mode + GVM"
    echo "  ./redamon.sh kb build lite    # Build Knowledge Base"
    echo "  ./redamon.sh kb update        # Refresh all KB sources"
    echo "  ./redamon.sh kb stats         # Show KB chunk counts"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

cd "$SCRIPT_DIR"

case "${1:-help}" in
    install) cmd_install "${2:-}" ;;
    update)  cmd_update ;;
    up)
        if [[ "${2:-}" == "dev" ]]; then
            cmd_up_dev "${@:2}"
        else
            cmd_up
        fi
        ;;
    down)    cmd_down ;;
    clean)   cmd_clean ;;
    purge)   cmd_purge ;;
    status)  cmd_status ;;
    kb)
        shift
        case "${1:-help}" in
            build)   shift; cmd_kb_build   "${1:-lite}" ;;
            update)  shift; cmd_kb_update  "${1:-}" ;;
            rebuild) shift; cmd_kb_rebuild "${1:-standard}" ;;
            stats)   cmd_kb_stats ;;
            help|--help|-h|"") cmd_kb_help ;;
            *)
                error "Unknown kb command: $1"
                cmd_kb_help
                exit 1
                ;;
        esac
        ;;
    help|--help|-h) cmd_help ;;
    *)
        error "Unknown command: $1"
        cmd_help
        exit 1
        ;;
esac
