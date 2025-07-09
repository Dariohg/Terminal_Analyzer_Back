package main

import (
	"log"
	"net/http"
	"terminal-history-analyzer/internal/handlers"
	"terminal-history-analyzer/internal/parser"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// Configurar Gin
	r := gin.Default()

	// Configurar CORS
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:3000", "http://localhost:3001"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	r.Use(cors.New(config))

	// Rutas existentes
	api := r.Group("/api")
	{
		// Rutas originales
		api.POST("/upload", handlers.UploadHistory)
		api.POST("/analyze-text", handlers.AnalyzeText)
		api.GET("/demo", handlers.GetDemoAnalysis)

		// NUEVAS RUTAS MEJORADAS
		api.POST("/analyze-enhanced", handlers.AnalyzeEnhanced)
		api.POST("/validate-realtime", handlers.ValidateRealTime)
		api.GET("/spelling-suggestions/:command", handlers.GetSpellingSuggestions)
		api.GET("/command-help/:command", handlers.GetCommandHelp)
	}

	// Servir archivos estáticos del frontend (en producción)
	r.Static("/static", "./web/build/static")
	r.StaticFile("/", "./web/build/index.html")
	r.StaticFile("/favicon.ico", "./web/build/favicon.ico")

	// Ruta catch-all para SPA
	r.NoRoute(func(c *gin.Context) {
		c.File("./web/build/index.html")
	})

	log.Println("Servidor iniciado en http://localhost:8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal("Error al iniciar el servidor:", err)
	}
}

// internal/handlers/additional_endpoints.go
package handlers

import (
"net/http"
"terminal-history-analyzer/internal/parser"

"github.com/gin-gonic/gin"
)

// GetSpellingSuggestions devuelve sugerencias para un comando mal escrito
func GetSpellingSuggestions(c *gin.Context) {
	command := c.Param("command")
	if command == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Comando no especificado",
		})
		return
	}

	spellChecker := parser.NewSpellChecker()
	suggestion := spellChecker.CheckSpelling(command)

	if suggestion == nil {
		c.JSON(http.StatusOK, gin.H{
			"found": false,
			"message": "No se encontraron sugerencias para este comando",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"found": true,
		"suggestion": suggestion,
	})
}

// GetCommandHelp devuelve ayuda básica para un comando
func GetCommandHelp(c *gin.Context) {
	command := c.Param("command")
	if command == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Comando no especificado",
		})
		return
	}

	help := getCommandHelpInfo(command)

	c.JSON(http.StatusOK, gin.H{
		"command": command,
		"help": help,
	})
}

// getCommandHelpInfo devuelve información de ayuda para comandos comunes
func getCommandHelpInfo(command string) map[string]interface{} {
	helpDatabase := map[string]map[string]interface{}{
		"sudo": {
			"description": "Ejecuta comandos con privilegios de superusuario",
			"syntax": "sudo [opciones] comando [argumentos]",
			"common_flags": []string{"-u usuario", "-s", "-i"},
			"examples": []string{
				"sudo apt update",
				"sudo -u usuario comando",
				"sudo -s",
			},
			"security_notes": []string{
				"Use sudo solo cuando sea necesario",
				"Evite sudo su - o sudo -s",
				"Especifique comandos exactos en lugar de shells",
			},
		},
		"rm": {
			"description": "Elimina archivos y directorios",
			"syntax": "rm [opciones] archivo...",
			"common_flags": []string{"-r", "-f", "-i", "-v"},
			"examples": []string{
				"rm archivo.txt",
				"rm -r directorio/",
				"rm -i *.txt",
			},
			"security_notes": []string{
				"NUNCA use rm -rf /",
				"Use -i para confirmación interactiva",
				"Tenga cuidado con rutas absolutas",
			},
		},
		"chmod": {
			"description": "Cambia permisos de archivos y directorios",
			"syntax": "chmod [opciones] modo archivo...",
			"common_flags": []string{"-R", "-v"},
			"examples": []string{
				"chmod 755 script.sh",
				"chmod +x archivo",
				"chmod -R 644 directorio/",
			},
			"security_notes": []string{
				"Evite permisos 777 en producción",
				"Use permisos mínimos necesarios",
				"Tenga cuidado con -R en directorios del sistema",
			},
		},
		"curl": {
			"description": "Transfiere datos desde o hacia un servidor",
			"syntax": "curl [opciones] URL",
			"common_flags": []string{"-o archivo", "-L", "-H header", "-d datos"},
			"examples": []string{
				"curl https://api.ejemplo.com",
				"curl -o archivo.zip https://sitio.com/archivo.zip",
				"curl -H 'Content-Type: application/json' -d '{\"key\":\"value\"}' URL",
			},
			"security_notes": []string{
				"Verifique URLs antes de descargar",
				"Use HTTPS cuando sea posible",
				"Tenga cuidado con scripts de sitios desconocidos",
			},
		},
		"ssh": {
			"description": "Cliente SSH para conexiones remotas seguras",
			"syntax": "ssh [opciones] [usuario@]hostname [comando]",
			"common_flags": []string{"-p puerto", "-i clave_privada", "-L puerto_local:host:puerto_remoto"},
			"examples": []string{
				"ssh usuario@servidor.com",
				"ssh -p 2222 usuario@servidor.com",
				"ssh -i ~/.ssh/mi_clave usuario@servidor.com",
			},
			"security_notes": []string{
				"Use claves SSH en lugar de contraseñas",
				"Evite conectarse como root",
				"Verifique la identidad del servidor",
			},
		},
		"git": {
			"description": "Sistema de control de versiones distribuido",
			"syntax": "git [--version] [--help] <comando> [<args>]",
			"common_flags": []string{"clone", "add", "commit", "push", "pull", "status"},
			"examples": []string{
				"git clone https://github.com/usuario/repo.git",
				"git add .",
				"git commit -m 'mensaje'",
				"git push origin main",
			},
			"security_notes": []string{
				"Verifique la fuente de repositorios clonados",
				"Use HTTPS o SSH para clonado",
				"Revise commits antes de hacer merge",
			},
		},
	}

	if help, exists := helpDatabase[command]; exists {
		return help
	}

	// Ayuda genérica para comandos no reconocidos
	return map[string]interface{}{
		"description": "Comando no reconocido en la base de datos de ayuda",
		"suggestion": "Use 'man " + command + "' para obtener el manual completo",
		"alternatives": []string{
			"Verifique la ortografía del comando",
			"Use 'which " + command + "' para verificar si está instalado",
			"Consulte la documentación oficial",
		},
	}
}