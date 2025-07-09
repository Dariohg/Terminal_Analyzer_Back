package api

import (
	"terminal-history-analyzer/internal/handlers"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(router *gin.Engine) {
	// Grupo de rutas API v1
	v1 := router.Group("/api/v1")
	{
		// Rutas de análisis
		analysis := v1.Group("/analysis")
		{
			analysis.POST("/upload", handlers.UploadHistory)
			analysis.POST("/text", handlers.AnalyzeText)
			analysis.GET("/demo", handlers.GetDemoAnalysis)
		}

		// Rutas de información
		info := v1.Group("/info")
		{
			info.GET("/commands", handlers.GetKnownCommands)
			info.GET("/threats", handlers.GetThreatTypes)
		}
	}
}
