package utils

import (
	"bufio"
	"io"
	"strings"
)

// ReadHistoryFile lee un archivo de historial y retorna las líneas
func ReadHistoryFile(reader io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// ValidateFileContent valida que el contenido sea de un archivo de historial válido
func ValidateFileContent(content string) bool {
	lines := strings.Split(content, "\n")
	validLines := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Verificar que parezca un comando de shell
		if isValidShellCommand(line) {
			validLines++
		}
	}

	// Si al menos el 30% de las líneas no vacías parecen comandos válidos
	totalLines := len(lines)
	return validLines > 0 && float64(validLines)/float64(totalLines) > 0.3
}

// isValidShellCommand verifica si una línea parece un comando de shell válido
func isValidShellCommand(line string) bool {
	commonCommands := []string{
		"ls", "cd", "pwd", "echo", "cat", "grep", "find", "head", "tail",
		"sort", "uniq", "wc", "diff", "file", "which", "whereis", "man",
		"cp", "mv", "rm", "mkdir", "rmdir", "touch", "chmod", "chown",
		"tar", "gzip", "gunzip", "zip", "unzip", "wget", "curl", "ssh",
		"scp", "rsync", "git", "npm", "pip", "docker", "kubectl", "vim",
		"nano", "emacs", "sudo", "su", "ps", "top", "htop", "kill",
		"mount", "umount", "df", "du", "free", "uname", "whoami", "id",
		"history", "clear", "export", "alias", "unalias", "jobs", "fg", "bg",
		"nohup", "screen", "tmux", "awk", "sed", "tr", "cut", "paste",
		"xargs", "tee", "less", "more", "watch", "crontab", "systemctl",
		"service", "netstat", "ss", "lsof", "iptables", "route", "ping",
		"traceroute", "dig", "nslookup", "host", "curl", "telnet", "ftp",
		"sftp", "rsync", "scp", "nc", "netcat", "socat", "openssl",
	}

	// Extraer el primer token (comando)
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return false
	}

	command := parts[0]

	// Verificar si es un comando común
	for _, cmd := range commonCommands {
		if command == cmd {
			return true
		}
	}

	// Verificar si parece un comando válido (contiene caracteres de comando)
	if len(command) > 0 && (isAlphaNumeric(command) || strings.Contains(command, "/")) {
		return true
	}

	// Verificar si es un path ejecutable
	if strings.HasPrefix(command, "./") || strings.HasPrefix(command, "/") {
		return true
	}

	return false
}

// isAlphaNumeric verifica si una cadena contiene solo caracteres alfanuméricos y algunos especiales
func isAlphaNumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return len(s) > 0
}

// GetFileExtension obtiene la extensión de un archivo
func GetFileExtension(filename string) string {
	parts := strings.Split(filename, ".")
	if len(parts) > 1 {
		return "." + parts[len(parts)-1]
	}
	return ""
}

// IsHistoryFile verifica si un archivo es probablemente un archivo de historial
func IsHistoryFile(filename string) bool {
	historyNames := []string{
		"bash_history", ".bash_history",
		"zsh_history", ".zsh_history",
		"history", ".history",
		"fish_history", ".fish_history",
	}

	for _, name := range historyNames {
		if strings.Contains(filename, name) {
			return true
		}
	}

	return false
}

// SanitizeContent limpia el contenido removiendo caracteres problemáticos
func SanitizeContent(content string) string {
	// Remover caracteres de control excepto saltos de línea
	var result strings.Builder
	for _, r := range content {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 127) || r >= 160 {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// CountLines cuenta el número de líneas no vacías en el contenido
func CountLines(content string) int {
	lines := strings.Split(content, "\n")
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

// ExtractCommands extrae solo los comandos del contenido (primer token de cada línea)
func ExtractCommands(content string) []string {
	lines := strings.Split(content, "\n")
	var commands []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) > 0 {
			commands = append(commands, parts[0])
		}
	}

	return commands
}
