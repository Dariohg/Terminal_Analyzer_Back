package parser

import (
	"terminal-history-analyzer/internal/models"
)

// SpellChecker contiene la lógica para detectar comandos mal escritos
type SpellChecker struct {
	knownCommands map[string]bool
	commonTypos   map[string]string
}

// NewSpellChecker crea un nuevo verificador de ortografía
func NewSpellChecker() *SpellChecker {
	return &SpellChecker{
		knownCommands: getKnownCommands(),
		commonTypos:   getCommonTypos(),
	}
}

// getKnownCommands retorna una lista de comandos válidos conocidos
func getKnownCommands() map[string]bool {
	commands := []string{
		// Comandos básicos de navegación
		"ls", "cd", "pwd", "echo", "cat", "grep", "find", "head", "tail",
		"sort", "uniq", "wc", "diff", "file", "which", "whereis", "man",

		// Comandos de manejo de archivos
		"cp", "mv", "rm", "mkdir", "rmdir", "touch", "chmod", "chown",
		"tar", "gzip", "gunzip", "zip", "unzip", "ln", "du", "df",

		// Comandos de red
		"wget", "curl", "ssh", "scp", "rsync", "ping", "traceroute",
		"netstat", "ss", "iptables", "dig", "nslookup", "host",

		// Comandos de desarrollo
		"git", "npm", "pip", "node", "python", "python3", "java", "gcc",
		"make", "cmake", "mvn", "gradle", "docker", "kubectl",

		// Editores
		"vim", "vi", "nano", "emacs", "code", "gedit",

		// Comandos de sistema
		"sudo", "su", "ps", "top", "htop", "kill", "killall", "mount",
		"umount", "systemctl", "service", "crontab", "jobs", "bg", "fg",
		"nohup", "screen", "tmux", "history", "clear", "export", "alias",
		"unalias", "whoami", "id", "groups", "passwd", "useradd", "userdel",

		// Comandos de texto
		"awk", "sed", "tr", "cut", "paste", "xargs", "tee", "less", "more",
		"watch", "sort", "uniq", "comm", "join",

		// Comandos de red y comunicación
		"nc", "netcat", "socat", "openssl", "telnet", "ftp", "sftp",

		// Comandos de monitoreo
		"lsof", "strace", "ltrace", "tcpdump", "wireshark", "iotop",
		"vmstat", "iostat", "free", "uptime", "uname",
	}

	result := make(map[string]bool)
	for _, cmd := range commands {
		result[cmd] = true
	}
	return result
}

// getCommonTypos retorna errores típicos de escritura
func getCommonTypos() map[string]string {
	return map[string]string{
		// Errores comunes en comandos populares
		"suo":  "sudo",
		"sud":  "sudo",
		"sude": "sudo",
		"suod": "sudo",
		"dosu": "sudo",

		"sl":  "ls",
		"lss": "ls",
		"lst": "ls",
		"lis": "ls",

		"cta": "cat",
		"car": "cat",
		"act": "cat",

		"grp":   "grep",
		"gerp":  "grep",
		"grap":  "grep",
		"greap": "grep",

		"crul":  "curl",
		"culr":  "curl",
		"crurl": "curl",
		"curll": "curl",

		"wgte":  "wget",
		"wegt":  "wget",
		"wgett": "wget",

		"shh":  "ssh",
		"sssh": "ssh",
		"ssh2": "ssh",

		"chmdo":  "chmod",
		"chmood": "chmod",
		"chomd":  "chmod",
		"chmode": "chmod",

		"gti": "git",
		"gut": "git",
		"igt": "git",

		"vmi": "vim",
		"ivm": "vim",
		"vom": "vim",

		"tpo":  "top",
		"opt":  "top",
		"toop": "top",

		"kil":   "kill",
		"killl": "kill",
		"klil":  "kill",

		"mkdr":  "mkdir",
		"mkidr": "mkdir",
		"mdir":  "mkdir",

		"mvoe": "move",
		"moev": "move",

		"celar": "clear",
		"clera": "clear",
		"claer": "clear",
		"cler":  "clear",

		"ehco":  "echo",
		"ecoh":  "echo",
		"eecho": "echo",

		"hsitory": "history",
		"histroy": "history",
		"histry":  "history",

		"fdin": "find",
		"fnid": "find",
		"fidn": "find",

		"hcmod": "chmod",
		"chmo":  "chmod",
		"cmod":  "chmod",

		"owch":  "chown",
		"chon":  "chown",
		"chonw": "chown",

		"tuch":  "touch",
		"touhc": "touch",
		"toucn": "touch",

		"mkfs.":   "mkfs", // Comandos que empiezan con mkfs
		"umnt":    "umount",
		"unmount": "umount",
		"umoutn":  "umount",
	}
}

// CheckSpelling verifica si un comando está mal escrito
func (sc *SpellChecker) CheckSpelling(command string) *models.SpellingSuggestion {
	// Si el comando es válido, no hay problema
	if sc.knownCommands[command] {
		return nil
	}

	// Verificar errores conocidos primero
	if correction, exists := sc.commonTypos[command]; exists {
		return &models.SpellingSuggestion{
			Original:   command,
			Suggested:  correction,
			Confidence: 0.95,
			Reason:     "Error de tipeo común",
		}
	}

	// Buscar comandos similares usando distancia de Levenshtein
	suggestions := sc.findSimilarCommands(command, 2) // máximo 2 caracteres de diferencia

	if len(suggestions) > 0 {
		return &models.SpellingSuggestion{
			Original:     command,
			Suggested:    suggestions[0].Command,
			Confidence:   suggestions[0].Similarity,
			Reason:       "Comando similar encontrado",
			Alternatives: suggestions[1:], // Otras sugerencias
		}
	}

	return nil
}

// findSimilarCommands encuentra comandos similares usando distancia de Levenshtein
func (sc *SpellChecker) findSimilarCommands(command string, maxDistance int) []CommandSuggestion {
	var suggestions []CommandSuggestion

	for knownCmd := range sc.knownCommands {
		distance := levenshteinDistance(command, knownCmd)
		if distance <= maxDistance && distance > 0 {
			similarity := 1.0 - (float64(distance) / float64(max(len(command), len(knownCmd))))
			suggestions = append(suggestions, CommandSuggestion{
				Command:    knownCmd,
				Distance:   distance,
				Similarity: similarity,
			})
		}
	}

	// Ordenar por similitud descendente
	for i := 0; i < len(suggestions)-1; i++ {
		for j := i + 1; j < len(suggestions); j++ {
			if suggestions[i].Similarity < suggestions[j].Similarity {
				suggestions[i], suggestions[j] = suggestions[j], suggestions[i]
			}
		}
	}

	// Retornar máximo 3 sugerencias
	if len(suggestions) > 3 {
		suggestions = suggestions[:3]
	}

	return suggestions
}

// CommandSuggestion representa una sugerencia de comando
type CommandSuggestion struct {
	Command    string  `json:"command"`
	Distance   int     `json:"distance"`
	Similarity float64 `json:"similarity"`
}

// levenshteinDistance calcula la distancia de Levenshtein entre dos strings
func levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	// Crear matriz
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
	}

	// Inicializar primera fila y columna
	for i := 0; i <= len(s1); i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}

	// Llenar matriz
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}

			matrix[i][j] = min(
				matrix[i-1][j]+1,      // eliminación
				matrix[i][j-1]+1,      // inserción
				matrix[i-1][j-1]+cost, // sustitución
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// Funciones auxiliares
func min(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
