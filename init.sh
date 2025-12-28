#!/bin/bash
# Claude Orchestrator - Init Script
# Generated: 2025-12-28T16:05:03.956Z
#
# This script sets up the environment for the orchestration session.
# Run this at the start of each session to ensure proper setup.

set -e

echo "🚀 Initializing Claude Orchestrator environment..."

# Navigate to project (safely quoted)
cd '/Users/dimaz/workspace/projects/zsign-rust'

# Check git status
if git rev-parse --git-dir > /dev/null 2>&1; then
    echo "📦 Git repository detected"
    git status --short
else
    echo "⚠️  Not a git repository"
fi

# Check for common project files and run setup if found
if [ -f "package.json" ]; then
    echo "📦 Node.js project detected"
    if [ ! -d "node_modules" ]; then
        echo "   Installing dependencies..."
        npm install
    fi
fi

if [ -f "requirements.txt" ]; then
    echo "🐍 Python project detected"
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
fi

if [ -f "Cargo.toml" ]; then
    echo "🦀 Rust project detected"
fi

if [ -f "go.mod" ]; then
    echo "🐹 Go project detected"
fi

# Show orchestrator status
echo ""
echo "📊 Orchestrator Status:"
if [ -f ".claude/orchestrator/state.json" ]; then
    head -20 .claude/orchestrator/state.json
else
    echo "   No active session"
fi

echo ""
echo "✅ Environment ready!"
echo "   Use 'orchestrator_status' to check current progress"
