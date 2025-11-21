# Fish completion for om

# Helper function to get programs from JSON
function __om_programs
    set -l config_file "$HOME/.config/om/programs.json"
    if test -n "$XDG_CONFIG_HOME"
        set config_file "$XDG_CONFIG_HOME/om/programs.json"
    end
    
    if test -f "$config_file"
        grep -oP '^\s*"\K[^"]+(?="\s*:)' "$config_file" 2>/dev/null
    end
end

# Helper to check if we're using a subcommand
function __om_using_subcommand
    set -l cmd (commandline -opc)
    if test (count $cmd) -eq 1
        return 0
    end
    return 1
end

# Subcommands
complete -c om -f -n "__om_using_subcommand" -a "add" -d "Add or update a program"
complete -c om -f -n "__om_using_subcommand" -a "delete" -d "Delete a program"
complete -c om -f -n "__om_using_subcommand" -a "remove" -d "Delete a program (alias)"
complete -c om -f -n "__om_using_subcommand" -a "list" -d "List all programs"
complete -c om -f -n "__om_using_subcommand" -a "ls" -d "List all programs (alias)"
complete -c om -f -n "__om_using_subcommand" -a "info" -d "Show program details"
complete -c om -f -n "__om_using_subcommand" -a "search" -d "Search programs"
complete -c om -f -n "__om_using_subcommand" -a "find" -d "Search programs (alias)"
complete -c om -f -n "__om_using_subcommand" -a "edit" -d "Edit a program"
complete -c om -f -n "__om_using_subcommand" -a "path" -d "Show program command"
complete -c om -f -n "__om_using_subcommand" -a "desc" -d "Show program description"
complete -c om -f -n "__om_using_subcommand" -a "export" -d "Export to JSON file"
complete -c om -f -n "__om_using_subcommand" -a "import" -d "Import from JSON file"
complete -c om -f -n "__om_using_subcommand" -a "run" -d "Execute a program"

# Programs (for implicit execution)
complete -c om -f -n "__om_using_subcommand" -a "(__om_programs)"

# Global flags
complete -c om -s v -l verbose -d "Verbose output"
complete -c om -s h -l help -d "Show help message"
complete -c om -l version -d "Show version information"

# Flags for specific subcommands
complete -c om -n "__fish_seen_subcommand_from add delete remove import" -s f -l force -d "Skip confirmation/validation"

# Complete program names after certain commands
complete -c om -n "__fish_seen_subcommand_from delete remove info edit path desc run" -f -a "(__om_programs)"

# Complete files for export/import
complete -c om -n "__fish_seen_subcommand_from export import" -r