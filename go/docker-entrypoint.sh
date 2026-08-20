#!/bin/sh
# Generate the opencode config at container start so HARNESS_MODEL is honored.
#
# The Python image bakes opencode.json in with a hardcoded model and a
# single-model provider whitelist, which means HARNESS_MODEL is ignored by the
# opencode harness: even though the model is passed via `-m`, opencode falls
# back to (and restricts itself to) the baked model. Generating the config here
# from HARNESS_MODEL fixes that — the env var wins when set, and we fall back to
# the image default when it isn't.
set -e

# Precedence MUST match the node's own: config.py:79-84 /
# internal/config/ai.go:58 resolve the harness model as
# SEC_AF_MODEL > HARNESS_MODEL > "minimax/minimax-m2.5", and that value is what
# reaches opencode's `-m` flag. Reading only HARNESS_MODEL here would pin
# opencode.json (and its single-model provider whitelist) to the image default
# while the harness was invoked with SEC_AF_MODEL — precisely the mismatch this
# script exists to prevent. The image sets HARNESS_MODEL as an ENV, so the
# lower-precedence rung is always present and would always win.
MODEL="${SEC_AF_MODEL:-${HARNESS_MODEL:-openrouter/minimax/minimax-m2.5}}"

# opencode keys models under a provider by the slug *without* the provider
# prefix, e.g. "openrouter/minimax/minimax-m2.5" -> provider "openrouter",
# key "minimax/minimax-m2.5".
MODEL_KEY="${MODEL#openrouter/}"

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"
mkdir -p "$CONFIG_DIR"

cat > "$CONFIG_DIR/opencode.json" <<EOF
{"\$schema":"https://opencode.ai/config.json","model":"${MODEL}","small_model":"${MODEL}","provider":{"openrouter":{"options":{"apiKey":"{env:OPENROUTER_API_KEY}"},"models":{"${MODEL_KEY}":{}}}}}
EOF

exec "$@"
