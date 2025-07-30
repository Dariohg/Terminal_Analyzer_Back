package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"terminal-history-analyzer/internal/lexer"
	"terminal-history-analyzer/internal/models"
	"terminal-history-analyzer/internal/monitor"
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

// Monitor para análisis mejorado
var enhancedMonitor = monitor.NewMonitor()

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

	fmt.Printf("\n🚀 ANÁLISIS MEJORADO - %s (%d caracteres)\n", request.Filename, len(request.Content))
	fmt.Printf("🔧 Configuraciones: Real-time=%v, Spelling=%v\n", request.EnableRealTime, request.ValidateSpelling)
	fmt.Println("============================")

	// Realizar análisis completo CON monitoreo
	result := analyzeContentEnhancedWithMonitoring(request.Content)

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

// analyzeContentEnhancedWithMonitoring realiza el análisis mejorado con monitoreo
func analyzeContentEnhancedWithMonitoring(content string) *models.AnalysisResult {
	startTime := time.Now()

	// === FASE 1: ANÁLISIS LÉXICO MEJORADO ===
	fmt.Printf("🔍 Iniciando análisis léxico mejorado...\n")
	lexerMetric := enhancedMonitor.StartPhase("LÉXICO_MEJORADO")

	// Análisis léxico con más validaciones
	lex := lexer.NewLexer(content)
	tokens, lexErrors := lex.Tokenize()

	enhancedMonitor.EndPhase(lexerMetric)
	fmt.Printf("✅ Análisis léxico mejorado: %d tokens, %d errores\n", len(tokens), len(lexErrors))

	// === FASE 2: ANÁLISIS SINTÁCTICO CON SPELL CHECKER ===
	fmt.Printf("🔍 Iniciando análisis sintáctico con spell checker...\n")
	parserMetric := enhancedMonitor.StartPhase("SINTÁCTICO_SPELL")

	// Parser con SpellChecker
	p := parser.NewParser(tokens)
	commands, parseErrors, warnings := p.Parse()

	enhancedMonitor.EndPhase(parserMetric)
	fmt.Printf("✅ Análisis sintáctico con spell: %d comandos, %d errores, %d advertencias\n",
		len(commands), len(parseErrors), len(warnings))

	// === FASE 3: ANÁLISIS SEMÁNTICO CON SISTEMA DE ARCHIVOS ===
	fmt.Printf("🔍 Iniciando análisis semántico con filesystem...\n")
	semanticMetric := enhancedMonitor.StartPhase("SEMÁNTICO_FS")

	// Análisis semántico CON sistema de archivos
	analyzer := semantic.NewAnalyzer()
	threats, patterns, anomalies, fsAnalysis := analyzer.AnalyzeWithFileSystem(commands)

	enhancedMonitor.EndPhase(semanticMetric)
	fmt.Printf("✅ Análisis semántico FS: %d amenazas, %d patrones, %d anomalías, %d errores FS\n",
		len(threats), len(patterns), len(anomalies), len(fsAnalysis.Errors))

	// Generar reporte de monitoreo
	enhancedMonitor.FinishAnalysis()

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
		FileSystemAnalysis: &fsAnalysis, // Análisis adicional de filesystem
	}
}

// performQuickValidation realiza validación rápida para tiempo real
func performQuickValidation(content string) []string {
	var errors []string

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Validaciones rápidas
		if strings.Contains(line, "rm -rf /") {
			errors = append(errors, fmt.Sprintf("Línea %d: Comando extremadamente peligroso detectado", i+1))
		}

		if strings.Contains(line, "sudo rm -rf") {
			errors = append(errors, fmt.Sprintf("Línea %d: Eliminación peligrosa con privilegios elevados", i+1))
		}

		if strings.Contains(line, "dd if=") && strings.Contains(line, "of=/dev/") {
			errors = append(errors, fmt.Sprintf("Línea %d: Operación de disco peligrosa detectada", i+1))
		}
	}

	return errors
}
