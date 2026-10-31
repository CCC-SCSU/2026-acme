#!/usr/bin/env bash
# lib/prompts.sh - User interaction functions

# Yes/No prompt
prompt_yes_no() {
    local question="$1"
    local response
    
    while true; do
        read -r -p "${question} [y/n]: " response
        case "$response" in
            [Yy]|[Yy][Ee][Ss])
                return 0
                ;;
            [Nn]|[Nn][Oo])
                return 1
                ;;
            *)
                echo "Please answer yes or no."
                ;;
        esac
    done
}

# Menu selection
prompt_menu() {
    local title="$1"
    shift
    local options=("$@")
    
    echo "$title"
    for i in "${!options[@]}"; do
        echo "  $((i+1)). ${options[$i]}"
    done
    
    local selection
    while true; do
        read -r -p "Selection [1-${#options[@]}]: " selection
        if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#options[@]}" ]; then
            return $((selection-1))
        fi
        echo "Invalid selection. Please choose 1-${#options[@]}."
    done
}

# Confirmation prompt
prompt_confirm() {
    local message="$1"
    echo ""
    echo "=== CONFIRMATION REQUIRED ==="
    echo "$message"
    echo "============================="
    echo ""
    prompt_yes_no "Proceed?"
}

# Export functions
export -f prompt_yes_no prompt_menu prompt_confirm
