package handlers

import (
	"net/http"
	"strings"
	"time"

	"terminal-history-analyzer/internal/lexer"
	"terminal-history-analyzer/internal/models"
	"terminal-history-analyzer/internal/parser"
	"terminal-history-analyzer/internal/semantic"

	"github.com/gin-gonic/gin"
)

// EnhancedAnalysisRequest representa una petición de análisis mejorado
type EnhancedAnalysisRequest struct {
	Content          string `json:"content" binding:"required"`
	Filename         string `json:"filename,omitempty"`
	EnableRealTime   bool   `json:"enable_real_time,omitempty"`
	ValidateSpelling bool   `json:"validate_spelling,omitempty"`
}

// AnalyzeEnhanced maneja el análisis mejorado con validación sintáctica
func AnalyzeEnhanced(c *gin.Context) {
	var request EnhancedAnalysisRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Formato de datos inválido: " + err.Error(),
		})
		return
	}

	if request.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "El contenido no puede estar vacío",
		})
		return
	}

	// Realizar análisis completo
	result := analyzeContentEnhanced(request.Content)

	c.JSON(http.StatusOK, result)
}

// ValidateRealTime maneja la validación en tiempo real
func ValidateRealTime(c *gin.Context) {
	var request struct {
		Content string `json:"content" binding:"required"`
		Line    int    `json:"line,omitempty"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Formato de datos inválido",
		})
		return
	}

	// Realizar validación rápida
	validationErrors := performQuickValidation(request.Content)

	c.JSON(http.StatusOK, gin.H{
		"errors":    validationErrors,
		"timestamp": time.Now(),
	})
}

// analyzeContentEnhanced realiza el análisis completo con validación mejorada
func analyzeContentEnhanced(content string) *models.AnalysisResult {
	startTime := time.Now()

	// Análisis léxico
	lex := lexer.NewLexer(content)
	tokens, lexErrors := lex.Tokenize()

	// Análisis sintáctico con SpellChecker
	p := parser.NewParser(tokens)
	commands, parseErrors, warnings := p.Parse()

	// Análisis semántico CON sistema de archivos
	analyzer := semantic.NewAnalyzer()
	threats, patterns, anomalies, fsAnalysis := analyzer.AnalyzeWithFileSystem(commands)

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
		// NUEVO: Agregar análisis del sistema de archivos
		FileSystemAnalysis: &fsAnalysis,
	}
}

// performQuickValidation realiza una validación rápida para tiempo real
func performQuickValidation(content string) []map[string]interface{} {
	lines := strings.Split(content, "\n")
	var errors []map[string]interface{}

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Validaciones básicas rápidas
		words := strings.Fields(line)
		if len(words) == 0 {
			continue
		}

		command := words[0]

		// Verificar errores de ortografía comunes
		if suggestion := checkCommonTypos(command); suggestion != "" {
			errors = append(errors, map[string]interface{}{
				"line":       lineNum + 1,
				"type":       "spelling",
				"message":    "Posible error de ortografía",
				"original":   command,
				"suggestion": suggestion,
				"command":    line,
				"confidence": 0.9,
			})
		}

		// Verificar comandos peligrosos
		if isDangerousCommand(line) {
			errors = append(errors, map[string]interface{}{
				"line":    lineNum + 1,
				"type":    "security",
				"level":   "high",
				"message": "Comando potencialmente peligroso detectado",
				"command": line,
			})
		}
	}

	return errors
}

// checkCommonTypos verifica errores comunes de ortografía
func checkCommonTypos(command string) string {
	typos := map[string]string{
		"suo":   "sudo",
		"sl":    "ls",
		"cta":   "cat",
		"grp":   "grep",
		"crul":  "curl",
		"shh":   "ssh",
		"gti":   "git",
		"vmi":   "vim",
		"tpo":   "top",
		"kil":   "kill",
		"celar": "clear",
		"ehco":  "echo",
	}

	if correction, exists := typos[command]; exists {
		return correction
	}
	return ""
}

// isDangerousCommand verifica si un comando es peligroso
func isDangerousCommand(line string) bool {
	dangerousPatterns := []string{
		"sudo rm -rf",
		"rm -rf /",
		"chmod 777",
		"dd if=",
		"mkfs",
		"fdisk",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(line, pattern) {
			return true
		}
	}
	return false
}
