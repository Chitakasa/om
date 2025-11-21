#!/usr/bin/env bash
# Bash completion for om

_om_completions() {
    local cur prev words cword
    _init_completion || return

    # Commands
    local commands="add delete remove list ls info search find edit path desc export import run help version"
    
    # Get stored programs from JSON
    local programs=""
    local config_file="${XDG_CONFIG_HOME:-$HOME/.config}/om/programs.json"
    
    if [[ -f "$config_file" ]]; then
        # Extract program names from JSON
        programs=$(grep -oP '^\s*"\K[^"]+(?="\s*:)' "$config_file" 2>/dev/null | tr '\n' ' ')
    fi

    # First argument: complete commands and programs
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$commands $programs --help --version -h -v --verbose" -- "$cur") )
        return 0
    fi

    # Complete based on previous word
    case "$prev" in
        add)
            # No completion for name (user input)
            return 0
            ;;
        delete|remove|info|edit|path|desc|run)
            # Complete with program names
            COMPREPLY=( $(compgen -W "$programs" -- "$cur") )
            return 0
            ;;
        search|find)
            # No completion for search query
            return 0
            ;;
        export|import)
            # Complete with filenames
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        -f|--force|-v|--verbose)
            # After flags, complete with programs or commands
            COMPREPLY=( $(compgen -W "$commands $programs" -- "$cur") )
            return 0
            ;;
    esac

    # Check if we're after a subcommand
    local subcommand="${words[1]}"
    case "$subcommand" in
        add|delete|import|export)
            # Complete flags
            COMPREPLY=( $(compgen -W "-f --force -h --help" -- "$cur") )
            ;;
        *)
            # Default: complete with programs
            COMPREPLY=( $(compgen -W "$programs" -- "$cur") )
            ;;
    esac
}

complete -F _om_completions om