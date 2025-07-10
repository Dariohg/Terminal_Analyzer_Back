package main

import (
	"log"
	"terminal-history-analyzer/internal/handlers"

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

	// Rutas API v1 (para compatibilidad con el frontend actual)
	v1 := r.Group("/api/v1")
	{
		// Rutas que espera el frontend
		analysis := v1.Group("/analysis")
		{
			analysis.POST("/text", handlers.AnalyzeText)
			analysis.POST("/file", handlers.UploadHistory)
		}

		// Ruta de demo
		v1.GET("/demo", handlers.GetDemoAnalysis)
	}

	// Rutas API nuevas (para funcionalidades mejoradas)
	api := r.Group("/api")
	{
		// Rutas originales (mantener para compatibilidad)
		api.POST("/upload", handlers.UploadHistory)
		api.POST("/analyze-text", handlers.AnalyzeText)
		api.GET("/demo", handlers.GetDemoAnalysis)

		// Nuevas rutas mejoradas
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
	log.Println("Rutas disponibles:")
	log.Println("  POST /api/v1/analysis/text")
	log.Println("  POST /api/v1/analysis/file")
	log.Println("  GET  /api/v1/demo")
	log.Println("  POST /api/analyze-enhanced")
	log.Println("  POST /api/validate-realtime")

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Error al iniciar el servidor:", err)
	}
}
