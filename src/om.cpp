#include <iostream>
#include <fstream>
#include <filesystem>
#include <format>
#include <ranges>
#include <span>
#include <source_location>
#include <set>
#include <algorithm>
#include <unistd.h>
#include <sys/wait.h>
#include <pwd.h>
#include <nlohmann/json.hpp>
#include <CLI/CLI.hpp>

using json = nlohmann::json;
namespace fs = std::filesystem;
namespace rng = std::ranges;
namespace vw = std::views;

// =============================================================================
// Constants
// =============================================================================
constexpr const char* VERSION = "1.0.0";
constexpr const char* PROGRAM_NAME = "om";

// =============================================================================
// Error Handling
// =============================================================================
class ProgramError : public std::runtime_error {
public:
    ProgramError(const std::string& msg, 
                 std::source_location loc = std::source_location::current())
        : std::runtime_error(std::format("Error: {}", msg)) {}
};

// =============================================================================
// Utility Functions
// =============================================================================
[[nodiscard]] std::string getConfigPath() {
    auto getEnvOr = [](const char* var, const char* fallback) -> std::string {
        const char* val = getenv(var);
        return val ? std::string(val) : std::string(fallback);
    };

    std::string xdg = getEnvOr("XDG_CONFIG_HOME", "");
    if (!xdg.empty()) {
        return std::format("{}/om/programs.json", xdg);
    }

    std::string home = getEnvOr("HOME", getpwuid(getuid())->pw_dir);
    return std::format("{}/.config/om/programs.json", home);
}

std::string toLowerCase(std::string_view str) {
    std::string result{str};
    rng::transform(result, result.begin(), ::tolower);
    return result;
}

// =============================================================================
// ProgramManager Class
// =============================================================================
class ProgramManager {
private:
    std::string configPath;
    json data;
    bool verbose;
    
    inline static const std::set<std::string> RESERVED_NAMES = {
        "add", "delete", "remove", "list", "info", "search", 
        "edit", "path", "desc", "export", "import", "run", 
        "help", "version", "-h", "--help", "-v", "--version"
    };

    void ensureConfigExists() {
        fs::path dir = fs::path(configPath).parent_path();
        if (!fs::exists(dir)) {
            fs::create_directories(dir);
            if (verbose) {
                std::cout << std::format("Created config directory: {}\n", dir.string());
            }
        }
        if (!fs::exists(configPath)) {
            std::ofstream(configPath) << "{}";
            if (verbose) {
                std::cout << std::format("Created config file: {}\n", configPath);
            }
        }
    }

    void load() {
        ensureConfigExists();
        std::ifstream file(configPath);
        if (!file) {
            throw ProgramError("Cannot open config file");
        }
        
        try {
            file >> data;
        } catch (const std::exception& e) {
            std::cerr << std::format("Warning: Corrupted config - {}\n", e.what());
            std::cerr << "Creating backup and starting fresh...\n";
            
            if (fs::exists(configPath)) {
                fs::copy(configPath, configPath + ".backup", 
                        fs::copy_options::overwrite_existing);
                std::cerr << std::format("Backup saved to: {}.backup\n", configPath);
            }
            data = json::object();
        }
    }

    void save() {
        std::ofstream out(configPath);
        if (!out) throw ProgramError("Cannot write to config");
        out << data.dump(4);
        
        if (verbose) {
            std::cout << std::format("Config saved to: {}\n", configPath);
        }
    }

    [[nodiscard]] bool commandExists(const std::string& cmd) const {
        std::string checkCmd = std::format("command -v {} >/dev/null 2>&1", cmd);
        return system(checkCmd.c_str()) == 0;
    }

    [[nodiscard]] bool confirm(std::string_view prompt) const {
        std::cout << std::format("{} (y/n): ", prompt);
        char choice;
        std::cin >> choice;
        std::cin.ignore(10000, '\n');
        return (choice == 'y' || choice == 'Y');
    }

    [[nodiscard]] std::string escapeShellArg(std::string_view arg) const {
        std::string escaped{arg};
        size_t pos = 0;
        while ((pos = escaped.find('\'', pos)) != std::string::npos) {
            escaped.replace(pos, 1, "'\\''");
            pos += 4;
        }
        return std::format("'{}'", escaped);
    }

    [[nodiscard]] bool isReservedName(std::string_view name) const {
        return RESERVED_NAMES.contains(std::string(name));
    }

public:
    explicit ProgramManager(const std::string& path, bool verb = false) 
        : configPath(path), verbose(verb) {
        load();
    }

    void add(std::string_view name, std::string_view cmd, 
             std::string_view desc, bool force = false) {
        if (name.empty() || cmd.empty()) {
            throw ProgramError("Name and command cannot be empty");
        }

        if (isReservedName(name)) {
            std::cerr << std::format("Warning: '{}' is a reserved command name\n", name);
            std::cerr << std::format("You will need to use '{} run {}' to execute it\n", 
                PROGRAM_NAME, name);
            if (!force && !confirm("Continue anyway?")) {
                std::cout << "Cancelled.\n";
                return;
            }
        }

        auto firstSpace = rng::find(cmd, ' ');
        std::string baseCmd(cmd.begin(), firstSpace);
        bool isPath = (baseCmd.find('/') != std::string::npos);

        if (!force) {
            if (!isPath && !commandExists(baseCmd)) {
                std::cerr << std::format("Warning: '{}' not found in PATH\n", baseCmd);
                if (!confirm("Add anyway?")) {
                    std::cout << "Cancelled.\n";
                    return;
                }
            } else if (isPath && !fs::exists(baseCmd)) {
                std::cerr << std::format("Warning: File '{}' does not exist\n", baseCmd);
                if (!confirm("Add anyway?")) {
                    std::cout << "Cancelled.\n";
                    return;
                }
            }
        }

        bool isUpdate = data.contains(name);
        data[name] = {{"cmd", cmd}, {"desc", desc}};
        save();

        std::cout << std::format("{} {}\n", 
                                isUpdate ? "✓ Updated:" : "✓ Added:",
                                name);
        
        if (verbose) {
            std::cout << std::format("  Command:     {}\n", cmd);
            std::cout << std::format("  Description: {}\n", desc);
        }
    }

    void remove(std::string_view name, bool force = false) {
        if (!data.contains(name)) {
            throw ProgramError(std::format("Program '{}' not found", name));
        }

        if (!force) {
            auto cmdStr = data[name]["cmd"].template get<std::string>();
            std::cout << std::format("Delete '{}' ({})?\n", name, cmdStr);
            if (!confirm("Are you sure?")) {
                std::cout << "Cancelled.\n";
                return;
            }
        }

        data.erase(std::string(name));
        save();
        std::cout << std::format("✓ Deleted: {}\n", name);
    }

    void list() const {
        if (data.empty()) {
            std::cout << "No programs stored.\n";
            std::cout << std::format("Use '{} add <name> <cmd> <desc>' to add one.\n", PROGRAM_NAME);
            return;
        }

        std::cout << std::format("\nStored Programs ({}):\n", data.size());
        std::cout << std::string(60, '=') << "\n";
        
        for (const auto& [key, val] : data.items()) {
            std::string desc = val.contains("desc") ? 
                val["desc"].template get<std::string>() : "";
            
            std::cout << std::format("  {}", key);
            if (!desc.empty()) {
                std::cout << std::format(" - {}", desc);
            }
            std::cout << "\n";
            
            if (verbose && val.contains("cmd")) {
                std::cout << std::format("    → {}\n", 
                    val["cmd"].template get<std::string>());
            }
        }
        std::cout << std::string(60, '=') << "\n";
    }

    void info(std::string_view name) const {
        if (!data.contains(name)) {
            throw ProgramError(std::format("Program '{}' not found", name));
        }

        std::cout << std::format("\nProgram: {}\n", name);
        std::cout << std::string(40, '-') << "\n";
        
        if (data[name].contains("cmd")) {
            std::cout << std::format("Command:     {}\n", 
                data[name]["cmd"].template get<std::string>());
        }
        if (data[name].contains("desc")) {
            std::cout << std::format("Description: {}\n", 
                data[name]["desc"].template get<std::string>());
        }
        
        if (isReservedName(name)) {
            std::cout << "\nNote: This is a reserved command name.\n";
            std::cout << std::format("Use '{} run {}' to execute.\n", PROGRAM_NAME, name);
        }
    }

    void search(std::string_view query) const {
        std::string lowerQuery = toLowerCase(query);
        std::cout << std::format("\nSearch results for '{}':\n", query);
        
        bool found = false;
        for (const auto& [key, val] : data.items()) {
            std::string desc = val.contains("desc") ? 
                val["desc"].template get<std::string>() : "";
            std::string cmd = val.contains("cmd") ? 
                val["cmd"].template get<std::string>() : "";
            
            if (toLowerCase(key).find(lowerQuery) != std::string::npos || 
                toLowerCase(desc).find(lowerQuery) != std::string::npos ||
                toLowerCase(cmd).find(lowerQuery) != std::string::npos) {
                
                std::cout << std::format("  {}", key);
                if (!desc.empty()) {
                    std::cout << std::format(" - {}", desc);
                }
                std::cout << "\n";
                
                if (verbose) {
                    std::cout << std::format("    → {}\n", cmd);
                }
                found = true;
            }
        }

        if (!found) {
            std::cout << "  No matches found.\n";
        }
    }

    void edit(std::string_view name) {
        if (!data.contains(name)) {
            throw ProgramError(std::format("Program '{}' not found", name));
        }

        std::string currentCmd = data[name].value("cmd", "");
        std::string currentDesc = data[name].value("desc", "");

        std::cout << std::format("Editing: {}\n\n", name);
        
        std::cout << std::format("Current command: {}\n", currentCmd);
        std::cout << "New command (Enter to keep current): ";
        std::string newCmd;
        std::getline(std::cin, newCmd);
        if (!newCmd.empty()) {
            currentCmd = newCmd;
        }

        std::cout << std::format("\nCurrent description: {}\n", currentDesc);
        std::cout << "New description (Enter to keep current): ";
        std::string newDesc;
        std::getline(std::cin, newDesc);
        if (!newDesc.empty()) {
            currentDesc = newDesc;
        }

        data[name] = {{"cmd", currentCmd}, {"desc", currentDesc}};
        save();

        std::cout << std::format("\n✓ Updated: {}\n", name);
    }

    void execute(std::string_view name, std::span<const std::string> args) {
        if (!data.contains(name) || !data[name].contains("cmd")) {
            throw ProgramError(std::format("Program '{}' not found.\n"
                "Run '{} list' to see available programs.", name, PROGRAM_NAME));
        }

        std::string cmd = data[name]["cmd"].template get<std::string>();
        
        for (const auto& arg : args) {
            cmd += " " + escapeShellArg(arg);
        }

        if (verbose) {
            std::cout << std::format("Executing: {}\n", cmd);
            std::cout << std::string(60, '-') << "\n";
        }
        
        int result = system(cmd.c_str());
        
        if (verbose) {
            std::cout << std::string(60, '-') << "\n";
            if (result == 0) {
                std::cout << "✓ Success\n";
            } else {
                std::cerr << std::format("✗ Failed with exit code {}\n", 
                    WEXITSTATUS(result));
            }
        } else if (result != 0) {
            std::cerr << std::format("Command failed with exit code {}\n", 
                WEXITSTATUS(result));
        }
    }

    void exportTo(std::string_view filename) {
        std::ofstream out(filename.data());
        if (!out) {
            throw ProgramError(std::format("Cannot write to {}", filename));
        }
        out << data.dump(4);
        std::cout << std::format("✓ Exported {} programs to: {}\n", 
            data.size(), filename);
    }

    void importFrom(std::string_view filename, bool force = false) {
        if (!fs::exists(filename.data())) {
            throw ProgramError(std::format("File not found: {}", filename));
        }

        std::ifstream file(filename.data());
        json importData;
        
        try {
            file >> importData;
        } catch (const std::exception& e) {
            throw ProgramError(std::format("Invalid JSON file: {}", e.what()));
        }

        if (!force) {
            std::cout << std::format("Import {} programs from '{}'?\n", 
                importData.size(), filename);
            std::cout << "Warning: This will overwrite existing programs with the same name.\n";
            
            if (!confirm("Continue?")) {
                std::cout << "Cancelled.\n";
                return;
            }
        }

        int added = 0, updated = 0;
        for (const auto& [key, val] : importData.items()) {
            if (data.contains(key)) {
                updated++;
            } else {
                added++;
            }
            data[key] = val;
        }
        
        save();
        std::cout << std::format("✓ Imported: {} new, {} updated\n", added, updated);
    }

    [[nodiscard]] std::string getPath(std::string_view name) const {
        if (!data.contains(name) || !data[name].contains("cmd")) {
            throw ProgramError(std::format("Program '{}' not found", name));
        }
        return data[name]["cmd"].template get<std::string>();
    }

    [[nodiscard]] std::string getDescription(std::string_view name) const {
        if (!data.contains(name) || !data[name].contains("desc")) {
            throw ProgramError(std::format("No description for '{}'", name));
        }
        return data[name]["desc"].template get<std::string>();
    }

    void showVersion() const {
        std::cout << std::format("{} version {}\n", PROGRAM_NAME, VERSION);
        std::cout << std::format("Config: {}\n", configPath);
        std::cout << std::format("Programs: {}\n", data.size());
    }
};

// =============================================================================
// Main
// =============================================================================
int main(int argc, char* argv[]) {
    CLI::App app{std::format("{} - Program Manager", PROGRAM_NAME)};
    app.footer(std::format("Config: {}\nVersion: {}", getConfigPath(), VERSION));
    app.require_subcommand(0, 1);
    app.set_help_flag("-h,--help", "Show help message");

    bool verbose = false;
    app.add_flag("-v,--verbose", verbose, "Verbose output");

    bool showVersion = false;
    app.add_flag("--version", showVersion, "Show version information");

    std::string name, cmd, desc, query, filename;
    bool force = false;
    std::vector<std::string> execArgs;

    auto add_cmd = app.add_subcommand("add", "Add or update a program");
    add_cmd->add_option("name", name, "Program name")->required();
    add_cmd->add_option("command", cmd, "Command to execute")->required();
    add_cmd->add_option("description", desc, "Description")->required();
    add_cmd->add_flag("-f,--force", force, "Skip validation and warnings");

    auto del_cmd = app.add_subcommand("delete", "Delete a program");
    del_cmd->alias("remove");
    del_cmd->add_option("name", name, "Program name")->required();
    del_cmd->add_flag("-f,--force", force, "Skip confirmation");

    auto list_cmd = app.add_subcommand("list", "List all stored programs");
    list_cmd->alias("ls");

    auto info_cmd = app.add_subcommand("info", "Show detailed program information");
    info_cmd->add_option("name", name, "Program name")->required();

    auto search_cmd = app.add_subcommand("search", "Search programs (case-insensitive)");
    search_cmd->alias("find");
    search_cmd->add_option("query", query, "Search query")->required();

    auto edit_cmd = app.add_subcommand("edit", "Edit a program interactively");
    edit_cmd->add_option("name", name, "Program name")->required();

    auto path_cmd = app.add_subcommand("path", "Show program command");
    path_cmd->add_option("name", name, "Program name")->required();

    auto desc_cmd = app.add_subcommand("desc", "Show program description");
    desc_cmd->add_option("name", name, "Program name")->required();

    auto export_cmd = app.add_subcommand("export", "Export programs to JSON file");
    export_cmd->add_option("file", filename, "Output filename")->required();

    auto import_cmd = app.add_subcommand("import", "Import programs from JSON file");
    import_cmd->add_option("file", filename, "Input filename")->required();
    import_cmd->add_flag("-f,--force", force, "Skip confirmation");

    auto exec_cmd = app.add_subcommand("run", "Execute a stored program");
    exec_cmd->add_option("name", name, "Program name")->required();
    exec_cmd->add_option("args", execArgs, "Arguments to pass to the program");

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        if (argc > 1 && argv[1][0] != '-') {
            name = argv[1];
            for (int i = 2; i < argc; ++i) {
                execArgs.push_back(argv[i]);
            }
            try {
                ProgramManager pm(getConfigPath(), false);
                pm.execute(name, execArgs);
                return 0;
            } catch (const std::exception& e) {
                std::cerr << e.what() << "\n";
                return 1;
            }
        }
        return app.exit(e);
    }

    if (showVersion) {
        ProgramManager pm(getConfigPath(), verbose);
        pm.showVersion();
        return 0;
    }

    // Create ProgramManager once with correct verbose setting
    ProgramManager pm(getConfigPath(), verbose);

    try {
        if (*add_cmd) pm.add(name, cmd, desc, force);
        else if (*del_cmd) pm.remove(name, force);
        else if (*list_cmd) pm.list();
        else if (*info_cmd) pm.info(name);
        else if (*search_cmd) pm.search(query);
        else if (*edit_cmd) pm.edit(name);
        else if (*path_cmd) std::cout << pm.getPath(name) << "\n";
        else if (*desc_cmd) std::cout << pm.getDescription(name) << "\n";
        else if (*export_cmd) pm.exportTo(filename);
        else if (*import_cmd) pm.importFrom(filename, force);
        else if (*exec_cmd) pm.execute(name, execArgs);
        else std::cout << app.help();
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}