#!/bin/bash
# Development Workflow Script for XSSniper
# This script helps you work with original files and deploy obfuscated versions

set -e

ORIGINAL_DIR="/Users/ameer/XssTool/original_backup"
REPO_DIR="/Users/ameer/XssTool/XssTool"
OBFUSCATOR="$ORIGINAL_DIR/obfuscator.py"

echo "🔧 XSSniper Development Workflow"
echo "=================================="

case "$1" in
    "edit")
        if [ -z "$2" ]; then
            echo "Usage: ./dev_workflow.sh edit <filename>"
            echo "Available files:"
            ls $ORIGINAL_DIR/*.py | grep -E "(XSSniper|payload_tester|param_discovery)\.py$" | xargs basename -s .py
            exit 1
        fi
        
        FILENAME="$2.py"
        if [ ! -f "$ORIGINAL_DIR/$FILENAME" ]; then
            echo "❌ File $FILENAME not found in original backup"
            exit 1
        fi
        
        echo "📝 Opening $FILENAME for editing..."
        echo "💡 Original file: $ORIGINAL_DIR/$FILENAME"
        code "$ORIGINAL_DIR/$FILENAME" || nano "$ORIGINAL_DIR/$FILENAME"
        ;;
        
    "deploy")
        echo "🚀 Deploying changes to repository..."
        
        # Obfuscate main Python files
        # Handle XSSniper.py (was xss_scanner.py)
        if [ -f "$ORIGINAL_DIR/XSSniper.py" ]; then
            echo "🔒 Obfuscating XSSniper.py..."
            python3 "$OBFUSCATOR" "$ORIGINAL_DIR/XSSniper.py" "$REPO_DIR/XSSniper.py"
        fi
        
        # Handle other files
        for file in payload_tester param_discovery; do
            if [ -f "$ORIGINAL_DIR/${file}.py" ]; then
                echo "🔒 Obfuscating ${file}.py..."
                python3 "$OBFUSCATOR" "$ORIGINAL_DIR/${file}.py" "$REPO_DIR/${file}.py"
            fi
        done
        
        # Copy non-Python files that might have changed
        for file in xss_payloads.json banner.txt setup.sh; do
            if [ -f "$ORIGINAL_DIR/$file" ]; then
                echo "📋 Copying $file..."
                cp "$ORIGINAL_DIR/$file" "$REPO_DIR/"
            fi
        done
        
        echo "✅ Deployment complete!"
        echo "📝 Next steps:"
        echo "   1. Test your changes: cd $REPO_DIR && python3 XSSniper.py --help"
        echo "   2. Commit: git add . && git commit -m 'Your commit message'"
        echo "   3. Push: git push"
        ;;
        
    "backup")
        echo "💾 Creating backup of current repository state..."
        BACKUP_NAME="backup_$(date +%Y%m%d_%H%M%S)"
        cp -r "$REPO_DIR" "/Users/ameer/XssTool/${BACKUP_NAME}"
        echo "✅ Backup created: /Users/ameer/XssTool/${BACKUP_NAME}"
        ;;
        
    "status")
        echo "📊 Current Status:"
        echo "==================="
        echo "Original files: $ORIGINAL_DIR"
        echo "Repository: $REPO_DIR"
        echo ""
        echo "📁 Original Python files:"
        ls -la "$ORIGINAL_DIR"/*.py | grep -E "(XSSniper|payload_tester|param_discovery)\.py$"
        echo ""
        echo "📁 Repository Python files (obfuscated):"
        ls -la "$REPO_DIR"/*.py
        echo ""
        echo "🔍 Git status:"
        cd "$REPO_DIR" && git status --short
        ;;
        
    "test")
        echo "🧪 Testing current repository version..."
        cd "$REPO_DIR"
        python3 XSSniper.py --help
        echo "✅ Basic test passed!"
        ;;
        
    *)
        echo "Usage: ./dev_workflow.sh <command>"
        echo ""
        echo "Commands:"
        echo "  edit <filename>    - Edit original source file (XSSniper, payload_tester, param_discovery)"
        echo "  deploy            - Obfuscate and deploy changes to repository"
        echo "  backup            - Create backup of current repository state"
        echo "  status            - Show current status of files and git"
        echo "  test              - Test current repository version"
        echo ""
        echo "Example workflow:"
        echo "  1. ./dev_workflow.sh edit XSSniper"
        echo "  2. Make your changes"
        echo "  3. ./dev_workflow.sh deploy"
        echo "  4. ./dev_workflow.sh test"
        echo "  5. git add . && git commit -m 'Your changes'"
        echo "  6. git push"
        ;;
esac
