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

// EnhancedAnalysisResponse representa una respuesta de análisis mejorado
type EnhancedAnalysisResponse struct {
	*models.AnalysisResult
	ValidationSummary *ValidationSummary `json:"validation_summary"`
	ProcessingDetails *ProcessingDetails `json:"processing_details"`
}

// ValidationSummary proporciona un resumen de las validaciones
type ValidationSummary struct {
	TotalLines         int                         `json:"total_lines"`
	ValidCommands      int                         `json:"valid_commands"`
	SpellingErrors     int                         `json:"spelling_errors"`
	StructureErrors    int                         `json:"structure_errors"`
	SecurityWarnings   int                         `json:"security_warnings"`
	TopSpellingErrors  []models.SpellingSuggestion `json:"top_spelling_errors"`
	CriticalIssues     []string                    `json:"critical_issues"`
	RecommendedActions []string                    `json:"recommended_actions"`
}

// ProcessingDetails proporciona detalles del procesamiento
type ProcessingDetails struct {
	LexingTime      time.Duration `json:"lexing_time"`
	ParsingTime     time.Duration `json:"parsing_time"`
	SemanticTime    time.Duration `json:"semantic_time"`
	ValidationTime  time.Duration `json:"validation_time"`
	TotalTime       time.Duration `json:"total_time"`
	TokensProcessed int           `json:"tokens_processed"`
	CommandsParsed  int           `json:"commands_parsed"`
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

	// Realizar análisis completo con medición de tiempo
	result, processingDetails := performEnhancedAnalysis(request.Content)

	// Generar resumen de validación
	validationSummary := generateValidationSummary(result)

	response := &EnhancedAnalysisResponse{
		AnalysisResult:    result,
		ValidationSummary: validationSummary,
		ProcessingDetails: processingDetails,
	}

	c.JSON(http.StatusOK, response)
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

// performEnhancedAnalysis realiza el análisis completo con medición de tiempo
func performEnhancedAnalysis(content string) (*models.AnalysisResult, *ProcessingDetails) {
	totalStart := time.Now()
	details := &ProcessingDetails{}

	// Análisis léxico con medición
	lexStart := time.Now()
	lex := lexer.NewLexer(content)
	tokens, lexErrors := lex.Tokenize()
	details.LexingTime = time.Since(lexStart)
	details.TokensProcessed = len(tokens)

	// Análisis sintáctico mejorado con medición
	parseStart := time.Now()
	p := parser.NewParser(tokens)
	commands, parseErrors, warnings := p.Parse()
	details.ParsingTime = time.Since(parseStart)
	details.CommandsParsed = len(commands)

	// Análisis semántico con medición
	semanticStart := time.Now()
	analyzer := semantic.NewAnalyzer()
	threats, patterns, anomalies := analyzer.Analyze(commands)
	details.SemanticTime = time.Since(semanticStart)

	// Validación adicional con medición
	validationStart := time.Now()

	// Aquí se pueden agregar validaciones adicionales específicas
	enhancedParseErrors := enhanceParseErrors(parseErrors, commands)

	details.ValidationTime = time.Since(validationStart)
	details.TotalTime = time.Since(totalStart)

	// Estadísticas
	commandFreq := calculateCommandFrequency(commands)
	threatCount := calculateThreatCount(threats)
	tokenStats := calculateTokenStats(tokens)

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
			ProcessingTime:   details.TotalTime,
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
			ParseErrors: enhancedParseErrors,
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
	}, details
}

// enhanceParseErrors mejora los errores de parsing con información adicional
func enhanceParseErrors(errors []models.SyntaxError, commands []models.CommandAST) []models.SyntaxError {
	enhanced := make([]models.SyntaxError, len(errors))

	for i, error := range errors {
		enhanced[i] = error

		// Aquí se pueden agregar mejoras específicas a cada error
		// Por ejemplo, agregar sugerencias contextuales
		if error.Type == "unknown_command" {
			// Buscar comandos similares en los comandos válidos parseados
			similarCommands := findSimilarCommandsInParsed(error.Command, commands)
			if len(similarCommands) > 0 {
				// Agregar sugerencias basadas en comandos similares encontrados
				enhanced[i].Message += ". Comandos similares encontrados: " +
					joinStringSlice(similarCommands, ", ")
			}
		}
	}

	return enhanced
}

// performQuickValidation realiza una validación rápida para tiempo real
func performQuickValidation(content string) []map[string]interface{} {
	lines := splitLines(content)
	var errors []map[string]interface{}

	for lineNum, line := range lines {
		if line == "" || line[0] == '#' {
			continue
		}

		// Validaciones básicas rápidas
		words := splitWords(line)
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

// generateValidationSummary genera un resumen de las validaciones
func generateValidationSummary(result *models.AnalysisResult) *ValidationSummary {
	summary := &ValidationSummary{
		TotalLines:         0, // Calculado dinámicamente
		ValidCommands:      len(result.SyntaxAnalysis.Commands),
		SpellingErrors:     0,
		StructureErrors:    0,
		SecurityWarnings:   0,
		CriticalIssues:     []string{},
		RecommendedActions: []string{},
	}

	// Contar tipos de errores
	for _, error := range result.SyntaxAnalysis.ParseErrors {
		switch error.Type {
		case "spelling_error":
			summary.SpellingErrors++
			if error.Validation.SpellingSuggestion != nil {
				summary.TopSpellingErrors = append(summary.TopSpellingErrors,
					*error.Validation.SpellingSuggestion)
			}
		case "missing_argument", "malformed_syntax":
			summary.StructureErrors++
		}

		if len(error.Validation.SecurityWarnings) > 0 {
			summary.SecurityWarnings += len(error.Validation.SecurityWarnings)
		}
	}

	// Identificar problemas críticos
	for _, threat := range result.SemanticAnalysis.Threats {
		if threat.Level == models.CRITICAL || threat.Level == models.HIGH {
			summary.CriticalIssues = append(summary.CriticalIssues, threat.Description)
		}
	}

	// Generar recomendaciones
	if summary.SpellingErrors > 0 {
		summary.RecommendedActions = append(summary.RecommendedActions,
			"Revisar y corregir errores de ortografía en comandos")
	}
	if summary.SecurityWarnings > 0 {
		summary.RecommendedActions = append(summary.RecommendedActions,
			"Evaluar comandos marcados como riesgos de seguridad")
	}
	if len(summary.CriticalIssues) > 0 {
		summary.RecommendedActions = append(summary.RecommendedActions,
			"Atender inmediatamente las amenazas críticas detectadas")
	}

	// Limitar los errores de ortografía mostrados
	if len(summary.TopSpellingErrors) > 5 {
		summary.TopSpellingErrors = summary.TopSpellingErrors[:5]
	}

	return summary
}

// Funciones auxiliares

func findSimilarCommandsInParsed(target string, commands []models.CommandAST) []string {
	var similar []string
	seen := make(map[string]bool)

	for _, cmd := range commands {
		if !seen[cmd.Command] && isStringsSimilar(target, cmd.Command) {
			similar = append(similar, cmd.Command)
			seen[cmd.Command] = true
		}
	}

	return similar
}

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
		if contains(line, pattern) {
			return true
		}
	}
	return false
}

func splitLines(content string) []string {
	return strings.Split(content, "\n")
}

func splitWords(line string) []string {
	return strings.Fields(strings.TrimSpace(line))
}

func isStringsSimilar(a, b string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}

	// Calcular distancia de Levenshtein simple
	if abs(len(a)-len(b)) > 2 {
		return false
	}

	return levenshteinDistance(a, b) <= 2
}

func joinStringSlice(slice []string, separator string) string {
	return strings.Join(slice, separator)
}

func contains(text, pattern string) bool {
	return strings.Contains(text, pattern)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
	}

	for i := 0; i <= len(s1); i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}

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

func min(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}
