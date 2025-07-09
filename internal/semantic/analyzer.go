package semantic

import (
	"regexp"
	"strings"

	"terminal-history-analyzer/internal/models"
)

type Analyzer struct {
	threats   []models.ThreatDetection
	patterns  []models.PatternMatch
	anomalies []models.Anomaly
}

// Patrones de amenazas
var (
	// Comandos extremadamente peligrosos
	criticalPatterns = map[string]string{
		`rm\s+-rf\s+/`:         "Eliminación recursiva del sistema de archivos raíz",
		`dd\s+if=.*of=/dev/sd`: "Sobrescritura directa de disco",
		`mkfs`:                 "Formateo de sistema de archivos",
		`fdisk.*-l`:            "Manipulación de particiones",
		`chmod\s+777\s+/`:      "Permisos peligrosos en directorio raíz",
	}

	// Comandos con escalación de privilegios
	privilegePatterns = map[string]string{
		`sudo\s+su\s*-`: "Cambio a usuario root",
		`sudo\s+-s`:     "Shell con privilegios elevados",
		`sudo\s+passwd`: "Cambio de contraseña con sudo",
		`su\s+root`:     "Cambio directo a root",
	}

	// Patrones de red sospechosos
	networkPatterns = map[string]string{
		`wget.*http://[^/]*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`: "Descarga desde IP directa",
		`curl.*http://[^/]*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`: "Descarga con curl desde IP",
		`ssh.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`:              "Conexión SSH a IP directa",
		`nc\s+.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`:            "Netcat a IP directa",
	}

	// Dominios sospechosos conocidos
	suspiciousDomains = []string{
		"pastebin.com", "hastebin.com", "ix.io", "0x0.st",
		"temp.sh", "transfer.sh", "file.io",
	}

	// Extensiones de archivos peligrosas
	dangerousExtensions = []string{
		".sh", ".py", ".pl", ".exe", ".bat", ".cmd", ".scr",
	}
)

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		threats:   make([]models.ThreatDetection, 0),
		patterns:  make([]models.PatternMatch, 0),
		anomalies: make([]models.Anomaly, 0),
	}
}

func (a *Analyzer) Analyze(commands []models.CommandAST) ([]models.ThreatDetection, []models.PatternMatch, []models.Anomaly) {
	for _, cmd := range commands {
		a.analyzeCommand(cmd)
	}

	a.detectPatterns(commands)
	a.detectAnomalies(commands)

	return a.threats, a.patterns, a.anomalies
}

func (a *Analyzer) analyzeCommand(cmd models.CommandAST) {
	// Análisis de comandos críticos
	a.checkCriticalCommands(cmd)

	// Análisis de escalación de privilegios
	a.checkPrivilegeEscalation(cmd)

	// Análisis de actividad de red
	a.checkNetworkActivity(cmd)

	// Análisis de manipulación de archivos
	a.checkFileManipulation(cmd)

	// Análisis de comandos encadenados peligrosos
	a.checkCommandChaining(cmd)

	// Análisis de descargas sospechosas
	a.checkSuspiciousDownloads(cmd)
}

func (a *Analyzer) checkCriticalCommands(cmd models.CommandAST) {
	commandLine := cmd.Raw

	for pattern, description := range criticalPatterns {
		if matched, _ := regexp.MatchString(pattern, commandLine); matched {
			a.addThreat(models.CRITICAL, "critical_command", description, cmd)
			return
		}
	}

	// Verificaciones específicas adicionales
	if cmd.Command == "rm" {
		if hasFlag(cmd, "rf") || hasFlag(cmd, "r") && hasFlag(cmd, "f") {
			for _, arg := range cmd.Arguments {
				if strings.Contains(arg, "/") && !strings.HasPrefix(arg, "./") {
					a.addThreat(models.HIGH, "dangerous_deletion",
						"Eliminación recursiva forzada en directorio del sistema", cmd)
				}
			}
		}
	}

	if cmd.Command == "dd" {
		for _, arg := range cmd.Arguments {
			if strings.Contains(arg, "/dev/") {
				a.addThreat(models.CRITICAL, "disk_manipulation",
					"Manipulación directa de dispositivo de disco", cmd)
			}
		}
	}
}

func (a *Analyzer) checkPrivilegeEscalation(cmd models.CommandAST) {
	commandLine := cmd.Raw

	for pattern, description := range privilegePatterns {
		if matched, _ := regexp.MatchString(pattern, commandLine); matched {
			a.addThreat(models.HIGH, "privilege_escalation", description, cmd)
			return
		}
	}

	if cmd.Command == "sudo" {
		if len(cmd.Arguments) > 0 {
			sudoCmd := cmd.Arguments[0]
			if contains([]string{"rm", "chmod", "chown", "mount", "umount"}, sudoCmd) {
				a.addThreat(models.MEDIUM, "sudo_dangerous",
					"Uso de sudo con comando potencialmente peligroso", cmd)
			}
		}
	}
}

func (a *Analyzer) checkNetworkActivity(cmd models.CommandAST) {
	commandLine := cmd.Raw

	for pattern, description := range networkPatterns {
		if matched, _ := regexp.MatchString(pattern, commandLine); matched {
			a.addThreat(models.MEDIUM, "suspicious_network", description, cmd)
		}
	}

	if contains([]string{"wget", "curl"}, cmd.Command) {
		for _, arg := range cmd.Arguments {
			if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
				// Verificar dominios sospechosos
				for _, domain := range suspiciousDomains {
					if strings.Contains(arg, domain) {
						a.addThreat(models.MEDIUM, "suspicious_download",
							"Descarga desde dominio sospechoso: "+domain, cmd)
					}
				}

				// Verificar extensiones peligrosas
				for _, ext := range dangerousExtensions {
					if strings.HasSuffix(arg, ext) {
						a.addThreat(models.MEDIUM, "dangerous_file_download",
							"Descarga de archivo ejecutable", cmd)
					}
				}
			}
		}
	}

	if cmd.Command == "ssh" {
		// Verificar conexiones SSH sospechosas
		for _, arg := range cmd.Arguments {
			if strings.Contains(arg, "root@") {
				a.addThreat(models.MEDIUM, "root_ssh",
					"Conexión SSH como usuario root", cmd)
			}
			// IPs privadas sospechosas
			if matched, _ := regexp.MatchString(`192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.`, arg); matched {
				a.addThreat(models.LOW, "internal_ssh",
					"Conexión SSH a red interna", cmd)
			}
		}
	}
}

func (a *Analyzer) checkFileManipulation(cmd models.CommandAST) {
	if cmd.Command == "chmod" {
		for _, arg := range cmd.Arguments {
			if arg == "777" || arg == "666" || arg == "+x" {
				a.addThreat(models.MEDIUM, "dangerous_permissions",
					"Asignación de permisos peligrosos", cmd)
			}
		}
	}

	if cmd.Command == "chown" && len(cmd.Arguments) > 0 {
		if cmd.Arguments[0] == "root" || strings.Contains(cmd.Arguments[0], "root:") {
			a.addThreat(models.MEDIUM, "root_ownership",
				"Cambio de propietario a root", cmd)
		}
	}
}

func (a *Analyzer) checkCommandChaining(cmd models.CommandAST) {
	// Verificar pipes peligrosos
	if len(cmd.Pipes) > 0 {
		for _, pipe := range cmd.Pipes {
			if contains([]string{"sh", "bash", "zsh", "python", "perl"}, pipe.Command) {
				a.addThreat(models.HIGH, "pipe_execution",
					"Ejecución de código a través de pipe", cmd)
			}
		}
	}

	// Verificar redirecciones peligrosas
	for _, redirect := range cmd.Redirects {
		if strings.HasPrefix(redirect.Target, "/dev/") {
			a.addThreat(models.MEDIUM, "device_redirect",
				"Redirección a dispositivo del sistema", cmd)
		}
	}
}

func (a *Analyzer) checkSuspiciousDownloads(cmd models.CommandAST) {
	if contains([]string{"wget", "curl"}, cmd.Command) {
		// Buscar patrones de descarga y ejecución inmediata
		commandLine := cmd.Raw
		if matched, _ := regexp.MatchString(`(wget|curl).*\|.*sh`, commandLine); matched {
			a.addThreat(models.HIGH, "download_execute",
				"Descarga y ejecución inmediata de script", cmd)
		}
	}
}

func (a *Analyzer) detectPatterns(commands []models.CommandAST) {
	commandCount := make(map[string]int)

	// Contar frecuencia de comandos
	for _, cmd := range commands {
		commandCount[cmd.Command]++
	}

	// Detectar patrones de uso
	if commandCount["history"] > 1 {
		a.addPattern("history_clearing", "Múltiples intentos de limpiar historial",
			commandCount["history"], []string{"history -c", "history -w"})
	}

	if commandCount["sudo"] > 10 {
		a.addPattern("excessive_sudo", "Uso excesivo de sudo",
			commandCount["sudo"], []string{"sudo command1", "sudo command2"})
	}

	if commandCount["rm"] > 5 {
		a.addPattern("frequent_deletion", "Múltiples operaciones de eliminación",
			commandCount["rm"], []string{"rm file1", "rm -rf dir"})
	}
}

func (a *Analyzer) detectAnomalies(commands []models.CommandAST) {
	// Detectar comandos ejecutados a horas inusuales (si tuviéramos timestamps)

	// Detectar secuencias sospechosas
	for i := 0; i < len(commands)-1; i++ {
		current := commands[i]
		next := commands[i+1]

		// Descarga seguida de chmod +x
		if contains([]string{"wget", "curl"}, current.Command) &&
			next.Command == "chmod" && hasFlag(next, "x") {
			a.addAnomaly("download_execute_sequence",
				"Secuencia de descarga y dar permisos de ejecución",
				current.Raw+" ; "+next.Raw, current.Line)
		}

		// sudo seguido de rm
		if current.Command == "sudo" && next.Command == "rm" {
			a.addAnomaly("sudo_delete_sequence",
				"Uso de sudo seguido de eliminación",
				current.Raw+" ; "+next.Raw, current.Line)
		}
	}
}

func (a *Analyzer) addThreat(level models.ThreatLevel, threatType, description string, cmd models.CommandAST) {
	suggestions := generateSuggestions(threatType, cmd)

	threat := models.ThreatDetection{
		Type:        threatType,
		Level:       level,
		Description: description,
		Command:     cmd.Raw,
		Line:        cmd.Line,
		Suggestions: suggestions,
	}

	a.threats = append(a.threats, threat)
}

func (a *Analyzer) addPattern(patternType, description string, occurrences int, examples []string) {
	pattern := models.PatternMatch{
		Pattern:     patternType,
		Description: description,
		Occurrences: occurrences,
		Examples:    examples,
	}

	a.patterns = append(a.patterns, pattern)
}

func (a *Analyzer) addAnomaly(anomalyType, description, command string, line int) {
	anomaly := models.Anomaly{
		Type:        anomalyType,
		Description: description,
		Command:     command,
		Line:        line,
	}

	a.anomalies = append(a.anomalies, anomaly)
}

// Funciones auxiliares
func hasFlag(cmd models.CommandAST, flag string) bool {
	_, exists := cmd.Flags[flag]
	return exists
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func generateSuggestions(threatType string, cmd models.CommandAST) []string {
	switch threatType {
	case "critical_command":
		return []string{
			"Evite usar comandos destructivos en el sistema raíz",
			"Use comandos más específicos y menos peligrosos",
			"Verifique dos veces antes de ejecutar comandos críticos",
		}
	case "privilege_escalation":
		return []string{
			"Use sudo solo cuando sea absolutamente necesario",
			"Prefiera comandos específicos en lugar de shells elevados",
			"Considere usar herramientas específicas en lugar de acceso root",
		}
	case "suspicious_download":
		return []string{
			"Verifique la fuente antes de descargar archivos",
			"Use dominios oficiales y repositorios confiables",
			"Escanee archivos descargados antes de ejecutarlos",
		}
	default:
		return []string{
			"Revise el comando para asegurar que es seguro",
			"Considere alternativas más seguras",
		}
	}
}
