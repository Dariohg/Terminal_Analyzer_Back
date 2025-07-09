package lexer

import (
	"regexp"
	"strings"
	"unicode"

	"terminal-history-analyzer/internal/models"
)

type Lexer struct {
	input    string
	position int
	line     int
	tokens   []models.Token
	errors   []models.LexicalError
}

// Patrones regex para identificar tokens
var (
	urlPattern      = regexp.MustCompile(`https?://[^\s]+`)
	pathPattern     = regexp.MustCompile(`[~/][\w\-\./_]*`)
	flagPattern     = regexp.MustCompile(`-{1,2}[\w\-]+`)
	variablePattern = regexp.MustCompile(`\$\{?[\w_]+\}?`)
	numberPattern   = regexp.MustCompile(`^\d+$`)
)

// Comandos peligrosos conocidos
var dangerousCommands = map[string]bool{
	"rm":     true,
	"sudo":   true,
	"chmod":  true,
	"chown":  true,
	"dd":     true,
	"mkfs":   true,
	"fdisk":  true,
	"passwd": true,
	"su":     true,
}

func NewLexer(input string) *Lexer {
	return &Lexer{
		input:    input,
		position: 0,
		line:     1,
		tokens:   make([]models.Token, 0),
		errors:   make([]models.LexicalError, 0),
	}
}

func (l *Lexer) Tokenize() ([]models.Token, []models.LexicalError) {
	for l.position < len(l.input) {
		l.nextToken()
	}

	// Agregar token EOF
	l.addToken(models.EOF, "")

	return l.tokens, l.errors
}

func (l *Lexer) nextToken() {
	// Saltar espacios en blanco
	if l.isWhitespace() {
		l.consumeWhitespace()
		return
	}

	// Nueva línea
	if l.current() == '\n' {
		l.addToken(models.NEWLINE, "\n")
		l.position++
		l.line++
		return
	}

	// Comentarios
	if l.current() == '#' {
		l.consumeComment()
		return
	}

	// Pipes
	if l.current() == '|' {
		l.addToken(models.PIPE, "|")
		l.position++
		return
	}

	// Redirecciones
	if l.isRedirect() {
		l.consumeRedirect()
		return
	}

	// Strings con comillas
	if l.current() == '"' || l.current() == '\'' {
		l.consumeQuotedString()
		return
	}

	// Tokens de palabras
	if l.isAlphaNumeric() {
		l.consumeWord()
		return
	}

	// Operadores y otros caracteres
	if l.isOperator() {
		l.consumeOperator()
		return
	}

	// Carácter no reconocido
	l.addError("Carácter no reconocido: " + string(l.current()))
	l.position++
}

func (l *Lexer) consumeWord() {
	start := l.position

	// Consumir caracteres de palabra
	for l.position < len(l.input) && (l.isAlphaNumeric() || l.current() == '-' || l.current() == '_' || l.current() == '.') {
		l.position++
	}

	word := l.input[start:l.position]
	tokenType := l.classifyWord(word, start == 0 || l.isStartOfCommand(start))

	l.addToken(tokenType, word)
}

func (l *Lexer) classifyWord(word string, isCommand bool) models.TokenType {
	// URLs
	if urlPattern.MatchString(word) {
		return models.URL
	}

	// Paths
	if pathPattern.MatchString(word) {
		return models.PATH
	}

	// Flags
	if flagPattern.MatchString(word) {
		return models.FLAG
	}

	// Variables
	if variablePattern.MatchString(word) {
		return models.VARIABLE
	}

	// Números
	if numberPattern.MatchString(word) {
		return models.NUMBER
	}

	// Comando vs argumento
	if isCommand {
		return models.COMMAND
	}

	return models.ARGUMENT
}

func (l *Lexer) consumeQuotedString() {
	quote := l.current()
	start := l.position
	l.position++ // Saltar comilla inicial

	for l.position < len(l.input) && l.current() != quote {
		if l.current() == '\\' && l.position+1 < len(l.input) {
			l.position += 2 // Saltar carácter escapado
		} else {
			l.position++
		}
	}

	if l.position >= len(l.input) {
		l.addError("String sin cerrar")
		return
	}

	l.position++ // Saltar comilla final
	value := l.input[start:l.position]
	l.addToken(models.STRING, value)
}

func (l *Lexer) consumeComment() {
	start := l.position

	for l.position < len(l.input) && l.current() != '\n' {
		l.position++
	}

	comment := l.input[start:l.position]
	l.addToken(models.COMMENT, comment)
}

func (l *Lexer) consumeWhitespace() {
	start := l.position

	for l.position < len(l.input) && l.isWhitespace() {
		l.position++
	}

	whitespace := l.input[start:l.position]
	l.addToken(models.WHITESPACE, whitespace)
}

func (l *Lexer) consumeRedirect() {
	start := l.position

	if l.current() == '>' {
		l.position++
		if l.position < len(l.input) && l.current() == '>' {
			l.position++
		}
	} else if l.current() == '<' {
		l.position++
	}

	redirect := l.input[start:l.position]
	l.addToken(models.REDIRECT, redirect)
}

func (l *Lexer) consumeOperator() {
	operator := string(l.current())
	l.addToken(models.OPERATOR, operator)
	l.position++
}

func (l *Lexer) isWhitespace() bool {
	return l.current() == ' ' || l.current() == '\t'
}

func (l *Lexer) isRedirect() bool {
	return l.current() == '>' || l.current() == '<'
}

func (l *Lexer) isAlphaNumeric() bool {
	c := l.current()
	return unicode.IsLetter(c) || unicode.IsDigit(c) || c == '/' || c == '~'
}

func (l *Lexer) isOperator() bool {
	operators := ";&()[]{}*?$"
	return strings.ContainsRune(operators, l.current())
}

func (l *Lexer) isStartOfCommand(pos int) bool {
	// Revisar si estamos al inicio de una línea o después de ciertos operadores
	if pos == 0 {
		return true
	}

	// Buscar hacia atrás para ver si hay un separador de comando
	for i := pos - 1; i >= 0; i-- {
		c := l.input[i]
		if c == '\n' || c == ';' || c == '|' {
			return true
		}
		if c != ' ' && c != '\t' {
			return false
		}
	}

	return false
}

func (l *Lexer) current() rune {
	if l.position >= len(l.input) {
		return 0
	}
	return rune(l.input[l.position])
}

func (l *Lexer) addToken(tokenType models.TokenType, value string) {
	token := models.Token{
		Type:     tokenType,
		Value:    value,
		Position: l.position - len(value),
		Line:     l.line,
	}
	l.tokens = append(l.tokens, token)
}

func (l *Lexer) addError(message string) {
	error := models.LexicalError{
		Message:  message,
		Line:     l.line,
		Position: l.position,
	}
	l.errors = append(l.errors, error)
}
