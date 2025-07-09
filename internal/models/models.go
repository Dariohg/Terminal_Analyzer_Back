package models

import "time"

// Token representa un token léxico
type Token struct {
	Type     TokenType `json:"type"`
	Value    string    `json:"value"`
	Position int       `json:"position"`
	Line     int       `json:"line"`
}

// TokenType define los tipos de tokens
type TokenType string

const (
	// Tokens básicos
	COMMAND    TokenType = "COMMAND"
	ARGUMENT   TokenType = "ARGUMENT"
	FLAG       TokenType = "FLAG"
	PATH       TokenType = "PATH"
	URL        TokenType = "URL"
	PIPE       TokenType = "PIPE"
	REDIRECT   TokenType = "REDIRECT"
	VARIABLE   TokenType = "VARIABLE"
	STRING     TokenType = "STRING"
	NUMBER     TokenType = "NUMBER"
	OPERATOR   TokenType = "OPERATOR"
	COMMENT    TokenType = "COMMENT"
	WHITESPACE TokenType = "WHITESPACE"
	NEWLINE    TokenType = "NEWLINE"
	EOF        TokenType = "EOF"
)

// CommandAST representa un comando parseado
type CommandAST struct {
	Command   string            `json:"command"`
	Arguments []string          `json:"arguments"`
	Flags     map[string]string `json:"flags"`
	Pipes     []*CommandAST     `json:"pipes,omitempty"`
	Redirects []Redirect        `json:"redirects,omitempty"`
	Line      int               `json:"line"`
	Raw       string            `json:"raw"`
}

// Redirect representa una redirección
type Redirect struct {
	Type   string `json:"type"` // >, >>, <, etc.
	Target string `json:"target"`
}

// ThreatLevel define el nivel de amenaza
type ThreatLevel string

const (
	SAFE     ThreatLevel = "SAFE"
	LOW      ThreatLevel = "LOW"
	MEDIUM   ThreatLevel = "MEDIUM"
	HIGH     ThreatLevel = "HIGH"
	CRITICAL ThreatLevel = "CRITICAL"
)

// ThreatDetection representa una amenaza detectada
type ThreatDetection struct {
	Type        string      `json:"type"`
	Level       ThreatLevel `json:"level"`
	Description string      `json:"description"`
	Command     string      `json:"command"`
	Line        int         `json:"line"`
	Suggestions []string    `json:"suggestions,omitempty"`
}

// AnalysisResult representa el resultado completo del análisis
type AnalysisResult struct {
	Summary struct {
		TotalCommands    int                 `json:"total_commands"`
		UniqueCommands   int                 `json:"unique_commands"`
		ThreatCount      map[ThreatLevel]int `json:"threat_count"`
		MostUsedCommands []CommandFrequency  `json:"most_used_commands"`
		ProcessingTime   time.Duration       `json:"processing_time"`
	} `json:"summary"`

	LexicalAnalysis struct {
		Tokens     []Token           `json:"tokens"`
		TokenStats map[TokenType]int `json:"token_stats"`
		Errors     []LexicalError    `json:"errors"`
	} `json:"lexical_analysis"`

	SyntaxAnalysis struct {
		Commands    []CommandAST  `json:"commands"`
		ParseErrors []SyntaxError `json:"parse_errors"`
		Warnings    []string      `json:"warnings"`
	} `json:"syntax_analysis"`

	SemanticAnalysis struct {
		Threats   []ThreatDetection `json:"threats"`
		Patterns  []PatternMatch    `json:"patterns"`
		Anomalies []Anomaly         `json:"anomalies"`
	} `json:"semantic_analysis"`
}

// CommandFrequency representa la frecuencia de uso de comandos
type CommandFrequency struct {
	Command string `json:"command"`
	Count   int    `json:"count"`
}

// LexicalError representa un error léxico
type LexicalError struct {
	Message  string `json:"message"`
	Line     int    `json:"line"`
	Position int    `json:"position"`
}

// PatternMatch representa un patrón detectado
type PatternMatch struct {
	Pattern     string   `json:"pattern"`
	Description string   `json:"description"`
	Occurrences int      `json:"occurrences"`
	Examples    []string `json:"examples"`
}

// Anomaly representa una anomalía detectada
type Anomaly struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Command     string `json:"command"`
	Line        int    `json:"line"`
}

// UploadRequest representa una petición de análisis
type UploadRequest struct {
	Content  string `json:"content"`
	Filename string `json:"filename,omitempty"`
}

// SpellingSuggestion representa una sugerencia de corrección ortográfica
type SpellingSuggestion struct {
	Original     string              `json:"original"`
	Suggested    string              `json:"suggested"`
	Confidence   float64             `json:"confidence"`
	Reason       string              `json:"reason"`
	Alternatives []CommandSuggestion `json:"alternatives,omitempty"`
}

// CommandSuggestion representa una sugerencia alternativa de comando
type CommandSuggestion struct {
	Command    string  `json:"command"`
	Distance   int     `json:"distance"`
	Similarity float64 `json:"similarity"`
}

// SyntaxValidation representa validaciones sintácticas adicionales
type SyntaxValidation struct {
	IsValidCommand     bool                `json:"is_valid_command"`
	SpellingSuggestion *SpellingSuggestion `json:"spelling_suggestion,omitempty"`
	StructureErrors    []StructureError    `json:"structure_errors,omitempty"`
	SecurityWarnings   []SecurityWarning   `json:"security_warnings,omitempty"`
}

// StructureError representa errores en la estructura del comando
type StructureError struct {
	Type        string `json:"type"` // "missing_argument", "invalid_flag", "malformed_path", etc.
	Description string `json:"description"`
	Position    int    `json:"position"` // Posición del error en el comando
	Suggestion  string `json:"suggestion"`
}

// SecurityWarning representa advertencias de seguridad en tiempo de escritura
type SecurityWarning struct {
	Type        string `json:"type"`  // "dangerous_flag", "suspicious_path", "privilege_escalation", etc.
	Level       string `json:"level"` // "low", "medium", "high", "critical"
	Description string `json:"description"`
	Suggestion  string `json:"suggestion"`
}

type SyntaxError struct {
	Message    string           `json:"message"`
	Line       int              `json:"line"`
	Command    string           `json:"command"`
	Position   int              `json:"position,omitempty"`
	Type       string           `json:"type"` // "unknown_command", "malformed_syntax", "missing_argument"
	Validation SyntaxValidation `json:"validation"`
}

// CommandValidationResult representa el resultado de validar un comando
type CommandValidationResult struct {
	IsValid          bool                 `json:"is_valid"`
	Command          string               `json:"command"`
	ValidatedCommand *CommandAST          `json:"validated_command,omitempty"`
	Errors           []SyntaxError        `json:"errors,omitempty"`
	Warnings         []SecurityWarning    `json:"warnings,omitempty"`
	Suggestions      []SpellingSuggestion `json:"suggestions,omitempty"`
}
