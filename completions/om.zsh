#compdef om

_om() {
    local line state config_file programs

    # Get config file path
    config_file="${XDG_CONFIG_HOME:-$HOME/.config}/om/programs.json"

    # Extract programs from JSON
    if [[ -f "$config_file" ]]; then
        programs=(${(f)"$(grep -oP '^\s*"\K[^"]+(?="\s*:)' "$config_file" 2>/dev/null)"})
    fi

    _arguments -C \
        '(-v --verbose)'{-v,--verbose}'[Verbose output]' \
        '(- *)'{-h,--help}'[Show help message]' \
        '(- *)--version[Show version information]' \
        '1: :->command' \
        '*::arg:->args'

    case $state in
        command)
            local -a commands
            commands=(
                'add:Add or update a program'
                'delete:Delete a program'
                'remove:Delete a program (alias)'
                'list:List all programs'
                'ls:List all programs (alias)'
                'info:Show program details'
                'search:Search programs'
                'find:Search programs (alias)'
                'edit:Edit a program'
                'path:Show program command'
                'desc:Show program description'
                'export:Export to JSON file'
                'import:Import from JSON file'
                'run:Execute a program'
            )
            _describe 'command' commands
            _describe 'programs' programs
            ;;
        args)
            case $line[1] in
                add)
                    _arguments \
                        '1:name:()' \
                        '2:command:_files' \
                        '3:description:()' \
                        '(-f --force)'{-f,--force}'[Skip validation]'
                    ;;
                delete|remove|info|edit|path|desc)
                    _arguments \
                        '1:program:($programs)' \
                        '(-f --force)'{-f,--force}'[Skip confirmation]'
                    ;;
                search|find)
                    _arguments '1:query:()'
                    ;;
                export)
                    _arguments '1:file:_files'
                    ;;
                import)
                    _arguments \
                        '1:file:_files' \
                        '(-f --force)'{-f,--force}'[Skip confirmation]'
                    ;;
                run)
                    _arguments \
                        '1:program:($programs)' \
                        '*:args:()'
                    ;;
                *)
                    # For implicit execution
                    _arguments '*:args:()'
                    ;;
            esac
            ;;
    esac
}

_om "$@"