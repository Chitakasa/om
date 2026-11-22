package cli

import (
	"os"
	"strconv"
)

// termCols is shutil.get_terminal_size((80, 24)).columns: $COLUMNS, else the terminal, else 80.
func termCols() int {
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 0 {
		return c
	}
	if c := ttyCols(); c > 0 {
		return c
	}
	return 80
}
