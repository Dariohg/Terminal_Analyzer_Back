package main

import (
	"log"
	"net/http"
	"os"

	"terminal-history-analyzer/api"
	"terminal-history-analyzer/internal/middleware"
	"terminal-history-analyzer/pkg/config"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Cargar variables de entorno
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Cargar configuración
	cfg := config.Load()

	// Configurar Gin
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Crear router
	router := gin.Default()

	// Middleware
	router.Use(middleware.CORS())
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Rutas de salud
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "terminal-history-analyzer",
		})
	})

	// Configurar rutas de la API
	api.SetupRoutes(router)

	// Obtener puerto
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Servidor iniciando en puerto %s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
