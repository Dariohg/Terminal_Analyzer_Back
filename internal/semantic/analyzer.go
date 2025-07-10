package semantic

import (
	"regexp"
	"strings"

	"terminal-history-analyzer/internal/models"
)

type Analyzer struct {
	threats         []models.ThreatDetection
	patterns        []models.PatternMatch
	anomalies       []models.Anomaly
	filesystemState *FileSystemState
	fsErrors        []models.FileSystemError
}

// Patrones de amenazas existentes...
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
		threats:         make([]models.ThreatDetection, 0),
		patterns:        make([]models.PatternMatch, 0),
		anomalies:       make([]models.Anomaly, 0),
		filesystemState: NewFileSystemState(),
		fsErrors:        make([]models.FileSystemError, 0),
	}
}

// Analyze realiza el análisis semántico completo incluyendo el sistema de archivos
func (a *Analyzer) Analyze(commands []models.CommandAST) ([]models.ThreatDetection, []models.PatternMatch, []models.Anomaly) {
	// Análisis tradicional de amenazas
	for _, cmd := range commands {
		a.analyzeCommand(cmd)
	}

	a.detectPatterns(commands)
	a.detectAnomalies(commands)

	// NUEVO: Análisis del sistema de archivos
	a.analyzeFileSystem(commands)

	return a.threats, a.patterns, a.anomalies
}

// AnalyzeWithFileSystem realiza análisis completo y retorna también errores del sistema de archivos
func (a *Analyzer) AnalyzeWithFileSystem(commands []models.CommandAST) ([]models.ThreatDetection, []models.PatternMatch, []models.Anomaly, models.FileSystemAnalysis) {
	// Análisis estándar
	threats, patterns, anomalies := a.Analyze(commands)

	// Crear análisis del sistema de archivos
	fsAnalysis := models.FileSystemAnalysis{
		Errors:       a.fsErrors,
		State:        a.filesystemState.GetCurrentState(),
		Dependencies: a.buildDependencyChains(commands),
		Summary:      a.buildFileSystemSummary(),
	}

	return threats, patterns, anomalies, fsAnalysis
}

// analyzeFileSystem analiza cada comando en el contexto del sistema de archivos
func (a *Analyzer) analyzeFileSystem(commands []models.CommandAST) {
	for _, cmd := range commands {
		// Procesar el comando y detectar errores del sistema de archivos
		errors := a.filesystemState.ProcessCommand(cmd)
		a.fsErrors = append(a.fsErrors, errors...)

		// Convertir errores críticos del sistema de archivos en amenazas
		for _, fsError := range errors {
			if a.isFileSystemErrorCritical(fsError) {
				a.addThreat(models.HIGH, "filesystem_error", fsError.Description, cmd)
			}
		}
	}
}

// isFileSystemErrorCritical determina si un error del sistema de archivos es crítico
func (a *Analyzer) isFileSystemErrorCritical(fsError models.FileSystemError) bool {
	criticalTypes := []string{
		"directory_not_found",
		"file_not_found",
		"parent_directory_not_found",
	}

	for _, criticalType := range criticalTypes {
		if fsError.Type == criticalType {
			return true
		}
	}

	return false
}

// buildDependencyChains construye cadenas de dependencias entre comandos
func (a *Analyzer) buildDependencyChains(commands []models.CommandAST) []models.DependencyChain {
	var chains []models.DependencyChain

	for _, cmd := range commands {
		var dependencies []string

		// Analizar dependencias según el tipo de comando
		switch cmd.Command {
		case "cd":
			if len(cmd.Arguments) > 0 {
				dir := cmd.Arguments[0]
				if !a.filesystemState.directories[a.filesystemState.resolvePath(dir)] {
					dependencies = append(dependencies, "mkdir "+dir)
				}
			}

		case "cat", "less", "more", "head", "tail":
			for _, arg := range cmd.Arguments {
				if !strings.HasPrefix(arg, "-") {
					if !a.filesystemState.files[a.filesystemState.resolvePath(arg)] {
						dependencies = append(dependencies, "touch "+arg)
					}
				}
			}

		case "cp", "mv":
			if len(cmd.Arguments) >= 2 {
				source := cmd.Arguments[0]
				if !a.filesystemState.files[a.filesystemState.resolvePath(source)] &&
					!a.filesystemState.directories[a.filesystemState.resolvePath(source)] {
					dependencies = append(dependencies, "touch "+source)
				}
			}

		case "rm":
			for _, arg := range cmd.Arguments {
				if !strings.HasPrefix(arg, "-") {
					if !a.filesystemState.files[a.filesystemState.resolvePath(arg)] &&
						!a.filesystemState.directories[a.filesystemState.resolvePath(arg)] {
						dependencies = append(dependencies, "touch "+arg)
					}
				}
			}
		}

		if len(dependencies) > 0 {
			chains = append(chains, models.DependencyChain{
				Command:      cmd.Raw,
				Line:         cmd.Line,
				Dependencies: dependencies,
			})
		}
	}

	return chains
}

// buildFileSystemSummary construye un resumen del análisis del sistema de archivos
func (a *Analyzer) buildFileSystemSummary() models.FileSystemSummary {
	summary := models.FileSystemSummary{}

	// Contar tipos de errores
	for _, fsError := range a.fsErrors {
		summary.TotalErrors++

		switch fsError.Type {
		case "directory_not_found", "parent_directory_not_found":
			summary.MissingDirectories++
		case "file_not_found":
			summary.MissingFiles++
		case "directory_without_recursive", "missing_argument":
			summary.UnreachableCommands++
		}
	}

	// Contar elementos creados
	state := a.filesystemState.GetCurrentState()
	summary.DirectoriesCreated = len(state.CreatedDirs)
	summary.FilesCreated = len(state.CreatedFiles)

	return summary
}

// Funciones existentes del analizador semántico...

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
			if matched, _ := regexp.MatchString(`192\.168\.|10\.|172\.`, arg); matched {
				a.addThreat(models.LOW, "private_network_ssh",
					"Conexión SSH a red privada", cmd)
			}
		}
	}
}

func (a *Analyzer) checkFileManipulation(cmd models.CommandAST) {
	sensitiveFiles := []string{
		"/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/fstab",
		"/boot/", "/sys/", "/proc/", "~/.ssh/", "~/.bashrc",
	}

	if contains([]string{"cat", "less", "more", "head", "tail", "grep", "sed", "awk"}, cmd.Command) {
		for _, arg := range cmd.Arguments {
			for _, sensitive := range sensitiveFiles {
				if strings.Contains(arg, sensitive) {
					a.addThreat(models.MEDIUM, "sensitive_file_access",
						"Acceso a archivo sensible del sistema: "+arg, cmd)
				}
			}
		}
	}
}

func (a *Analyzer) checkCommandChaining(cmd models.CommandAST) {
	// Esta función necesitaría acceso a comandos anteriores para detectar patrones
	// Por ahora, detectamos algunos patrones básicos

	if strings.Contains(cmd.Raw, "&&") || strings.Contains(cmd.Raw, ";") {
		if strings.Contains(cmd.Raw, "wget") && strings.Contains(cmd.Raw, "chmod") {
			a.addThreat(models.HIGH, "download_execute_chain",
				"Cadena de descarga y ejecución detectada", cmd)
		}
	}
}

func (a *Analyzer) checkSuspiciousDownloads(cmd models.CommandAST) {
	if contains([]string{"wget", "curl"}, cmd.Command) {
		for _, arg := range cmd.Arguments {
			// Verificar patrones sospechosos en URLs
			suspiciousPatterns := []string{
				"malware", "payload", "exploit", "backdoor", "shell",
				"reverse", "bind", "nc", "netcat",
			}

			for _, pattern := range suspiciousPatterns {
				if strings.Contains(strings.ToLower(arg), pattern) {
					a.addThreat(models.HIGH, "suspicious_filename",
						"Descarga con nombre sospechoso: "+pattern, cmd)
				}
			}
		}
	}
}

func (a *Analyzer) detectPatterns(commands []models.CommandAST) {
	// Detectar patrones de uso
	commandFreq := make(map[string]int)
	sudoCommands := make([]string, 0)
	networkCommands := make([]string, 0)

	for _, cmd := range commands {
		commandFreq[cmd.Command]++

		if cmd.Command == "sudo" {
			sudoCommands = append(sudoCommands, cmd.Raw)
		}

		if contains([]string{"wget", "curl", "ssh", "scp", "rsync"}, cmd.Command) {
			networkCommands = append(networkCommands, cmd.Raw)
		}
	}

	// Patrón: Uso excesivo de sudo
	if len(sudoCommands) > 5 {
		a.addPattern("excessive_sudo", "Uso excesivo de sudo detectado", len(sudoCommands), sudoCommands[:3])
	}

	// Patrón: Múltiples comandos de red
	if len(networkCommands) > 3 {
		a.addPattern("multiple_network", "Múltiples comandos de red detectados", len(networkCommands), networkCommands[:3])
	}
}

func (a *Analyzer) detectAnomalies(commands []models.CommandAST) {
	// Detectar anomalías en secuencias de comandos
	for i := 0; i < len(commands)-1; i++ {
		current := commands[i]
		next := commands[i+1]

		// wget/curl seguido de chmod +x
		if contains([]string{"wget", "curl"}, current.Command) && next.Command == "chmod" && hasFlag(next, "x") {
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
	case "filesystem_error":
		return []string{
			"Verifique que los directorios y archivos existan antes de usarlos",
			"Cree las dependencias necesarias en el orden correcto",
			"Use comandos como 'ls' para verificar la existencia de archivos",
		}
	default:
		return []string{
			"Revise el comando para asegurar que es seguro",
			"Considere alternativas más seguras",
		}
	}
}
