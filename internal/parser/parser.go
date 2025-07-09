package parser

import (
	"strings"

	"terminal-history-analyzer/internal/models"
)

type Parser struct {
	tokens   []models.Token
	position int
	commands []models.CommandAST
	errors   []models.SyntaxError
	warnings []string
}

func NewParser(tokens []models.Token) *Parser {
	return &Parser{
		tokens:   filterTokens(tokens), // Filtrar whitespace y comentarios
		position: 0,
		commands: make([]models.CommandAST, 0),
		errors:   make([]models.SyntaxError, 0),
		warnings: make([]string, 0),
	}
}

func (p *Parser) Parse() ([]models.CommandAST, []models.SyntaxError, []string) {
	for p.position < len(p.tokens) {
		if p.current().Type == models.NEWLINE || p.current().Type == models.EOF {
			p.position++
			continue
		}

		cmd := p.parseCommand()
		if cmd != nil {
			p.commands = append(p.commands, *cmd)
		}
	}

	return p.commands, p.errors, p.warnings
}

func (p *Parser) parseCommand() *models.CommandAST {
	if p.position >= len(p.tokens) {
		return nil
	}

	startLine := p.current().Line
	var tokens []models.Token

	// Recopilar tokens hasta el final de la línea o comando
	for p.position < len(p.tokens) {
		token := p.current()

		if token.Type == models.NEWLINE || token.Type == models.EOF {
			break
		}

		// Si encontramos un punto y coma, es el final del comando actual
		if token.Type == models.OPERATOR && token.Value == ";" {
			p.position++ // Consumir el punto y coma
			break
		}

		tokens = append(tokens, token)
		p.position++
	}

	if len(tokens) == 0 {
		return nil
	}

	// Construir el comando raw
	var rawParts []string
	for _, token := range tokens {
		rawParts = append(rawParts, token.Value)
	}
	raw := strings.Join(rawParts, " ")

	// Verificar que el primer token sea un comando
	if tokens[0].Type != models.COMMAND {
		p.addError("Se esperaba un comando", startLine, raw)
		return nil
	}

	// Parsear la estructura del comando
	cmd := &models.CommandAST{
		Command:   tokens[0].Value,
		Arguments: make([]string, 0),
		Flags:     make(map[string]string),
		Redirects: make([]models.Redirect, 0),
		Line:      startLine,
		Raw:       raw,
	}

	// Verificar si hay pipes en el comando
	if p.hasPipes(tokens) {
		return p.parsePipedCommand(tokens, startLine, raw)
	}

	// Parsear argumentos, flags y redirecciones
	for i := 1; i < len(tokens); i++ {
		token := tokens[i]

		switch token.Type {
		case models.FLAG:
			p.parseFlag(cmd, tokens, &i)
		case models.REDIRECT:
			p.parseRedirect(cmd, tokens, &i)
		case models.ARGUMENT, models.PATH, models.URL, models.STRING, models.NUMBER:
			cmd.Arguments = append(cmd.Arguments, token.Value)
		case models.VARIABLE:
			cmd.Arguments = append(cmd.Arguments, token.Value)
			p.addWarning("Variable detectada: " + token.Value)
		default:
			p.addWarning("Token inesperado: " + token.Value)
		}
	}

	return cmd
}

func (p *Parser) parsePipedCommand(tokens []models.Token, startLine int, raw string) *models.CommandAST {
	// Dividir por pipes
	var commandGroups [][]models.Token
	var currentGroup []models.Token

	for _, token := range tokens {
		if token.Type == models.PIPE {
			if len(currentGroup) > 0 {
				commandGroups = append(commandGroups, currentGroup)
				currentGroup = make([]models.Token, 0)
			}
		} else {
			currentGroup = append(currentGroup, token)
		}
	}

	if len(currentGroup) > 0 {
		commandGroups = append(commandGroups, currentGroup)
	}

	if len(commandGroups) == 0 {
		return nil
	}

	// Parsear el primer comando
	mainCmd := p.parseSimpleCommand(commandGroups[0], startLine)
	if mainCmd == nil {
		return nil
	}

	mainCmd.Raw = raw

	// Parsear comandos en pipe
	for i := 1; i < len(commandGroups); i++ {
		pipeCmd := p.parseSimpleCommand(commandGroups[i], startLine)
		if pipeCmd != nil {
			mainCmd.Pipes = append(mainCmd.Pipes, pipeCmd)
		}
	}

	return mainCmd
}

func (p *Parser) parseSimpleCommand(tokens []models.Token, line int) *models.CommandAST {
	if len(tokens) == 0 || tokens[0].Type != models.COMMAND {
		return nil
	}

	cmd := &models.CommandAST{
		Command:   tokens[0].Value,
		Arguments: make([]string, 0),
		Flags:     make(map[string]string),
		Redirects: make([]models.Redirect, 0),
		Line:      line,
	}

	for i := 1; i < len(tokens); i++ {
		token := tokens[i]

		switch token.Type {
		case models.FLAG:
			p.parseFlag(cmd, tokens, &i)
		case models.REDIRECT:
			p.parseRedirect(cmd, tokens, &i)
		case models.ARGUMENT, models.PATH, models.URL, models.STRING, models.NUMBER, models.VARIABLE:
			cmd.Arguments = append(cmd.Arguments, token.Value)
		}
	}

	return cmd
}

func (p *Parser) parseFlag(cmd *models.CommandAST, tokens []models.Token, index *int) {
	flag := tokens[*index]
	flagName := strings.TrimLeft(flag.Value, "-")

	// Verificar si el flag tiene un valor
	if *index+1 < len(tokens) {
		nextToken := tokens[*index+1]
		if nextToken.Type == models.ARGUMENT || nextToken.Type == models.STRING ||
			nextToken.Type == models.NUMBER || nextToken.Type == models.PATH {
			cmd.Flags[flagName] = nextToken.Value
			*index++ // Consumir el valor del flag
		} else {
			cmd.Flags[flagName] = "true"
		}
	} else {
		cmd.Flags[flagName] = "true"
	}
}

func (p *Parser) parseRedirect(cmd *models.CommandAST, tokens []models.Token, index *int) {
	redirect := tokens[*index]

	// Buscar el target de la redirección
	if *index+1 < len(tokens) {
		target := tokens[*index+1]
		cmd.Redirects = append(cmd.Redirects, models.Redirect{
			Type:   redirect.Value,
			Target: target.Value,
		})
		*index++ // Consumir el target
	} else {
		p.addError("Redirección sin target", cmd.Line, cmd.Raw)
	}
}

func (p *Parser) hasPipes(tokens []models.Token) bool {
	for _, token := range tokens {
		if token.Type == models.PIPE {
			return true
		}
	}
	return false
}

func (p *Parser) current() models.Token {
	if p.position >= len(p.tokens) {
		return models.Token{Type: models.EOF}
	}
	return p.tokens[p.position]
}

func (p *Parser) addError(message string, line int, command string) {
	p.errors = append(p.errors, models.SyntaxError{
		Message: message,
		Line:    line,
		Command: command,
	})
}

func (p *Parser) addWarning(message string) {
	p.warnings = append(p.warnings, message)
}

// filterTokens elimina tokens innecesarios para el parsing
func filterTokens(tokens []models.Token) []models.Token {
	var filtered []models.Token

	for _, token := range tokens {
		// Mantener todos los tokens excepto whitespace y comentarios
		if token.Type != models.WHITESPACE && token.Type != models.COMMENT {
			filtered = append(filtered, token)
		}
	}

	return filtered
}
