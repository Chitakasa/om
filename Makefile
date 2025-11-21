# =============================================================================
# OM - Program Manager Makefile
# =============================================================================

# Compiler and flags
CXX := g++
CXXFLAGS := -std=c++20 -O2 -Wall -Wextra -pedantic
LDFLAGS := 
DEBUGFLAGS := -g -DDEBUG

# Directories
PREFIX := /usr/local
BINDIR := $(PREFIX)/bin
MANDIR := $(PREFIX)/share/man/man1
BASHCOMPDIR := $(PREFIX)/share/bash-completion/completions
ZSHCOMPDIR := $(PREFIX)/share/zsh/site-functions
FISHCOMPDIR := $(PREFIX)/share/fish/vendor_completions.d
DOCDIR := $(PREFIX)/share/doc/om
LICENSEDIR := $(PREFIX)/share/licenses/om

# Project files
TARGET := om
SRC := src/om.cpp
MANPAGE := om.1

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m  # No Color

# =============================================================================
# Targets
# =============================================================================

.PHONY: all clean install uninstall test debug help

# Default target
all: $(TARGET)

# Build release version
$(TARGET): $(SRC)
	@echo "$(BLUE)Building $(TARGET)...$(NC)"
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "$(GREEN)✓ Build successful!$(NC)"

# Build debug version
debug: CXXFLAGS += $(DEBUGFLAGS)
debug: clean $(TARGET)
	@echo "$(YELLOW)Debug build complete$(NC)"

# Install to system
install: $(TARGET)
	@echo "$(BLUE)Installing $(TARGET)...$(NC)"
	
	# Binary
	install -Dm755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	@echo "$(GREEN)✓ Installed binary to $(BINDIR)/$(TARGET)$(NC)"
	
	# Man page
	install -Dm644 $(MANPAGE) $(DESTDIR)$(MANDIR)/$(MANPAGE)
	gzip -f $(DESTDIR)$(MANDIR)/$(MANPAGE)
	@echo "$(GREEN)✓ Installed man page$(NC)"
	
	# Bash completion
	install -Dm644 completions/om.bash $(DESTDIR)$(BASHCOMPDIR)/om
	@echo "$(GREEN)✓ Installed bash completion$(NC)"
	
	# Zsh completion
	install -Dm644 completions/om.zsh $(DESTDIR)$(ZSHCOMPDIR)/_om
	@echo "$(GREEN)✓ Installed zsh completion$(NC)"
	
	# Fish completion
	install -Dm644 completions/om.fish $(DESTDIR)$(FISHCOMPDIR)/om.fish
	@echo "$(GREEN)✓ Installed fish completion$(NC)"
	
	# Documentation
	install -Dm644 README.md $(DESTDIR)$(DOCDIR)/README.md
	@echo "$(GREEN)✓ Installed documentation$(NC)"
	
	# License
	install -Dm644 LICENSE $(DESTDIR)$(LICENSEDIR)/LICENSE
	@echo "$(GREEN)✓ Installed license$(NC)"
	
	@echo ""
	@echo "$(GREEN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@echo "$(GREEN)Installation complete!$(NC)"
	@echo "$(GREEN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@echo ""
	@echo "Try running: $(BLUE)om --help$(NC)"
	@echo "Read the manual: $(BLUE)man om$(NC)"
	@echo ""

# Uninstall from system
uninstall:
	@echo "$(YELLOW)Uninstalling $(TARGET)...$(NC)"
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(MANDIR)/$(MANPAGE).gz
	rm -f $(DESTDIR)$(BASHCOMPDIR)/om
	rm -f $(DESTDIR)$(ZSHCOMPDIR)/_om
	rm -f $(DESTDIR)$(FISHCOMPDIR)/om.fish
	rm -rf $(DESTDIR)$(DOCDIR)
	rm -rf $(DESTDIR)$(LICENSEDIR)
	@echo "$(GREEN)✓ Uninstallation complete$(NC)"

# Clean build artifacts
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	rm -f $(TARGET)
	rm -f *.o
	rm -rf build/
	rm -f *.tar.gz
	@echo "$(GREEN)✓ Clean complete$(NC)"

# Run basic tests
test: $(TARGET)
	@echo "$(BLUE)Running tests...$(NC)"
	@./$(TARGET) --version || (echo "$(RED)✗ Version test failed$(NC)" && exit 1)
	@echo "$(GREEN)✓ All tests passed$(NC)"

# Create source tarball for distribution
dist: clean
	@echo "$(BLUE)Creating distribution tarball...$(NC)"
	tar -czf $(TARGET)-$(shell grep "VERSION =" src/om.cpp | cut -d'"' -f2).tar.gz \
		--transform 's,^,$(TARGET)/,' \
		src/ completions/ Makefile om.1 README.md LICENSE
	@echo "$(GREEN)✓ Tarball created$(NC)"

# Show help
help:
	@echo "$(BLUE)OM Makefile - Available Targets:$(NC)"
	@echo ""
	@echo "  $(GREEN)make$(NC)              - Build the program (release mode)"
	@echo "  $(GREEN)make debug$(NC)        - Build with debug symbols"
	@echo "  $(GREEN)make install$(NC)      - Install to $(PREFIX)"
	@echo "  $(GREEN)make uninstall$(NC)    - Remove from system"
	@echo "  $(GREEN)make clean$(NC)        - Remove build artifacts"
	@echo "  $(GREEN)make test$(NC)         - Run tests"
	@echo "  $(GREEN)make dist$(NC)         - Create distribution tarball"
	@echo "  $(GREEN)make help$(NC)         - Show this message"
	@echo ""
	@echo "$(YELLOW)Variables:$(NC)"
	@echo "  PREFIX=$(PREFIX)"
	@echo "  DESTDIR=$(DESTDIR)"
	@echo ""
	@echo "$(YELLOW)Examples:$(NC)"
	@echo "  Install to /usr:           $(BLUE)sudo make install PREFIX=/usr$(NC)"
	@echo "  Install to home directory: $(BLUE)make install PREFIX=\$$HOME/.local$(NC)"
	@echo ""