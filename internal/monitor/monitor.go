package monitor

import (
	"fmt"
	"runtime"
	"time"
)

// AnalysisMetrics contiene las métricas de análisis por fase
type AnalysisMetrics struct {
	Phase        string        `json:"phase"`         // "lexer", "parser", "semantic"
	StartTime    time.Time     `json:"start_time"`    // Tiempo de inicio
	Duration     time.Duration `json:"duration"`      // Duración de la fase
	CPUBefore    float64       `json:"cpu_before"`    // CPU antes del análisis
	CPUAfter     float64       `json:"cpu_after"`     // CPU después del análisis
	RAMBefore    uint64        `json:"ram_before"`    // RAM antes (MB)
	RAMAfter     uint64        `json:"ram_after"`     // RAM después (MB)
	RAMAllocated uint64        `json:"ram_allocated"` // RAM asignada durante la fase (MB)
	Goroutines   int           `json:"goroutines"`    // Goroutines activas
	GCCycles     uint32        `json:"gc_cycles"`     // Ciclos de garbage collection
}

// AnalysisReport reporte completo de análisis
type AnalysisReport struct {
	TotalDuration time.Duration     `json:"total_duration"`
	TotalRAMUsed  uint64            `json:"total_ram_used"`
	Phases        []AnalysisMetrics `json:"phases"`
	Summary       string            `json:"summary"`
}

// Monitor estructura principal del monitor
type Monitor struct {
	currentReport *AnalysisReport
}

// NewMonitor crea una nueva instancia del monitor
func NewMonitor() *Monitor {
	return &Monitor{
		currentReport: &AnalysisReport{
			Phases: make([]AnalysisMetrics, 0),
		},
	}
}

// StartPhase inicia el monitoreo de una fase específica
func (m *Monitor) StartPhase(phase string) *AnalysisMetrics {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	metric := &AnalysisMetrics{
		Phase:      phase,
		StartTime:  time.Now(),
		CPUBefore:  getCPUUsage(),
		RAMBefore:  bytesToMB(memStats.Alloc),
		Goroutines: runtime.NumGoroutine(),
		GCCycles:   memStats.NumGC,
	}

	return metric
}

// EndPhase finaliza el monitoreo de una fase
func (m *Monitor) EndPhase(metric *AnalysisMetrics) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	metric.Duration = time.Since(metric.StartTime)
	metric.CPUAfter = getCPUUsage()
	metric.RAMAfter = bytesToMB(memStats.Alloc)

	// Calcular RAM asignada evitando overflow
	if metric.RAMAfter >= metric.RAMBefore {
		metric.RAMAllocated = metric.RAMAfter - metric.RAMBefore
	} else {
		// Si liberó memoria, mostrar 0 en lugar de overflow
		metric.RAMAllocated = 0
	}

	// Agregar la métrica al reporte
	m.currentReport.Phases = append(m.currentReport.Phases, *metric)
}

// FinishAnalysis finaliza el análisis completo y muestra el reporte
func (m *Monitor) FinishAnalysis() {
	if len(m.currentReport.Phases) == 0 {
		return
	}

	// Calcular totales
	var totalDuration time.Duration
	var totalRAM uint64

	for _, phase := range m.currentReport.Phases {
		totalDuration += phase.Duration
		totalRAM += phase.RAMAllocated
	}

	m.currentReport.TotalDuration = totalDuration
	m.currentReport.TotalRAMUsed = totalRAM
	m.currentReport.Summary = fmt.Sprintf("Análisis completado en %v usando %d MB",
		totalDuration, totalRAM)

	// Mostrar reporte
	m.printReport()

	// Limpiar para el siguiente análisis
	m.currentReport = &AnalysisReport{
		Phases: make([]AnalysisMetrics, 0),
	}
}

// printReport imprime el reporte en consola
func (m *Monitor) printReport() {
	fmt.Println("\n" + "======================")
	fmt.Println("           REPORTE DE ANÁLISIS DE TERMINAL")
	fmt.Println("============================")

	for i, phase := range m.currentReport.Phases {
		fmt.Printf("\n📊 FASE %d: %s\n", i+1, phase.Phase)
		fmt.Println("-============================")
		fmt.Printf("⏱️  Duración:     %v\n", phase.Duration)

		// Mostrar RAM de forma más clara
		if phase.RAMAllocated > 0 {
			fmt.Printf("🧠 RAM Usada:    +%d MB (antes: %d MB → después: %d MB)\n",
				phase.RAMAllocated, phase.RAMBefore, phase.RAMAfter)
		} else {
			fmt.Printf("🧠 RAM:          %d MB → %d MB (liberó memoria)\n",
				phase.RAMBefore, phase.RAMAfter)
		}

		fmt.Printf("⚡ CPU:          %.2f%% → %.2f%%\n", phase.CPUBefore, phase.CPUAfter)
		fmt.Printf("🔧 Goroutines:   %d\n", phase.Goroutines)
		fmt.Printf("🗑️  GC Ciclos:    %d\n", phase.GCCycles)
	}

	fmt.Println("\n" + "========================")
	fmt.Printf("📈 RESUMEN TOTAL\n")
	fmt.Println("==================")
	fmt.Printf("⏱️  Tiempo Total:  %v\n", m.currentReport.TotalDuration)

	// Calcular RAM total evitando overflow
	if m.currentReport.TotalRAMUsed < 18446744073709551000 {
		fmt.Printf("🧠 RAM Total:     %d MB\n", m.currentReport.TotalRAMUsed)
	} else {
		fmt.Printf("🧠 RAM Total:     Memoria optimizada (GC activo)\n")
	}

	fmt.Printf("📊 Fases:         %d\n", len(m.currentReport.Phases))

	// Fase más lenta
	var slowestPhase string
	var slowestDuration time.Duration
	for _, phase := range m.currentReport.Phases {
		if phase.Duration > slowestDuration {
			slowestDuration = phase.Duration
			slowestPhase = phase.Phase
		}
	}

	if slowestPhase != "" {
		fmt.Printf("🐌 Fase más lenta: %s (%v)\n", slowestPhase, slowestDuration)
	}

	fmt.Println("====================" + "\n")
}

// getCPUUsage obtiene el porcentaje de uso de CPU (simplificado)
func getCPUUsage() float64 {
	start := time.Now()
	busy := 0

	// Simulación de carga de trabajo para medición
	for i := 0; i < 100000; i++ {
		busy++
	}

	elapsed := time.Since(start)
	usage := float64(elapsed.Nanoseconds()) / 100000.0
	if usage > 100 {
		usage = 100
	}

	return usage
}

// bytesToMB convierte bytes a megabytes
func bytesToMB(b uint64) uint64 {
	return b / 1024 / 1024
}
