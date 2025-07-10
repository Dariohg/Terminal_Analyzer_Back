package semantic

import (
	"path/filepath"
	"strings"
	"terminal-history-analyzer/internal/models"
)

// FileSystemState mantiene el estado virtual del sistema de archivos
type FileSystemState struct {
	currentDirectory string
	directories      map[string]bool // Directorios que han sido creados
	files            map[string]bool // Archivos que han sido creados
	initialDirs      map[string]bool // Directorios que existen por defecto
}

// NewFileSystemState crea un nuevo rastreador de estado del sistema de archivos
func NewFileSystemState() *FileSystemState {
	fs := &FileSystemState{
		currentDirectory: "/home/user", // Directorio inicial por defecto
		directories:      make(map[string]bool),
		files:            make(map[string]bool),
		initialDirs:      make(map[string]bool),
	}

	// Directorios que típicamente existen por defecto en un sistema Unix
	defaultDirs := []string{
		"/", "/home", "/home/user", "/tmp", "/var", "/usr", "/bin", "/etc",
		"/home/user/Documents", "/home/user/Downloads", "/home/user/Desktop",
		"/home/user/Pictures", "/home/user/Music", "/home/user/Videos",
		".", "..", "~",
	}

	for _, dir := range defaultDirs {
		fs.initialDirs[dir] = true
		fs.directories[dir] = true
	}

	return fs
}

// ProcessCommand procesa un comando y actualiza el estado del sistema de archivos
func (fs *FileSystemState) ProcessCommand(cmd models.CommandAST) []models.FileSystemError {
	var errors []models.FileSystemError

	switch cmd.Command {
	case "mkdir":
		errors = append(errors, fs.processMkdir(cmd)...)
	case "cd":
		errors = append(errors, fs.processCD(cmd)...)
	case "rmdir":
		errors = append(errors, fs.processRmdir(cmd)...)
	case "touch":
		errors = append(errors, fs.processTouch(cmd)...)
	case "rm":
		errors = append(errors, fs.processRm(cmd)...)
	case "cp":
		errors = append(errors, fs.processCp(cmd)...)
	case "mv":
		errors = append(errors, fs.processMv(cmd)...)
	case "cat", "less", "more", "head", "tail", "grep":
		errors = append(errors, fs.processFileRead(cmd)...)
	}

	return errors
}

// processMkdir maneja el comando mkdir
func (fs *FileSystemState) processMkdir(cmd models.CommandAST) []models.FileSystemError {
	var errors []models.FileSystemError

	if len(cmd.Arguments) == 0 {
		errors = append(errors, models.FileSystemError{
			Type:        "missing_argument",
			Command:     cmd.Raw,
			Line:        cmd.Line,
			Description: "mkdir requiere al menos un nombre de directorio",
			Suggestion:  "Especifique el nombre del directorio a crear: mkdir nombre_directorio",
		})
		return errors
	}

	for _, arg := range cmd.Arguments {
		// Resolver ruta absoluta
		absolutePath := fs.resolvePath(arg)

		// Verificar si el directorio ya existe
		if fs.directories[absolutePath] {
			errors = append(errors, models.FileSystemError{
				Type:        "directory_exists",
				Command:     cmd.Raw,
				Line:        cmd.Line,
				Path:        absolutePath,
				Description: "El directorio '" + arg + "' ya existe",
				Suggestion:  "Use un nombre diferente o verifique si realmente necesita crear este directorio",
			})
		} else {
			// Crear el directorio
			fs.directories[absolutePath] = true
		}
	}

	return errors
}

// processCD maneja el comando cd
func (fs *FileSystemState) processCD(cmd models.CommandAST) []models.FileSystemError {
	var errors []models.FileSystemError

	var targetDir string
	if len(cmd.Arguments) == 0 {
		// cd sin argumentos va al home
		targetDir = "/home/user"
	} else {
		targetDir = cmd.Arguments[0]
	}

	// Resolver ruta absoluta
	absolutePath := fs.resolvePath(targetDir)

	// Verificar si el directorio existe
	if !fs.directories[absolutePath] {
		errors = append(errors, models.FileSystemError{
			Type:        "directory_not_found",
			Command:     cmd.Raw,
			Line:        cmd.Line,
			Path:        absolutePath,
			Description: "No se puede cambiar al directorio '" + targetDir + "': directorio no encontrado",
			Suggestion:  "Primero cree el directorio con: mkdir " + targetDir,
			MissingDependency: &models.MissingDependency{
				Type:     "directory",
				Name:     targetDir,
				Required: "mkdir " + targetDir,
			},
		})
	} else {
		// Cambiar al directorio
		fs.currentDirectory = absolutePath
	}

	return errors
}

// processRmdir maneja el comando rmdir
func (fs *FileSystemState) processRmdir(cmd models.CommandAST) []models.FileSystemError {
	var errors []models.FileSystemError

	if len(cmd.Arguments) == 0 {
		errors = append(errors, models.FileSystemError{
			Type:        "missing_argument",
			Command:     cmd.Raw,
			Line:        cmd.Line,
			Description: "rmdir requiere al menos un nombre de directorio",
			Suggestion:  "Especifique el nombre del directorio a eliminar: rmdir nombre_directorio",
		})
		return errors
	}

	for _, arg := range cmd.Arguments {
		absolutePath := fs.resolvePath(arg)

		// Verificar si el directorio existe
		if !fs.directories[absolutePath] {
			errors = append(errors, models.FileSystemError{
				Type:        "directory_not_found",
				Command:     cmd.Raw,
				Line:        cmd.Line,
				Path:        absolutePath,
				Description: "No se puede eliminar el directorio '" + arg + "': directorio no encontrado",
				Suggestion:  "Verifique que el directorio exista antes de intentar eliminarlo",
			})
		} else if fs.initialDirs[absolutePath] {
			errors = append(errors, models.FileSystemError{
				Type:        "system_directory",
				Command:     cmd.Raw,
				Line:        cmd.Line,
				Path:        absolutePath,
				Description: "Intento de eliminar directorio del sistema: " + arg,
				Suggestion:  "Evite eliminar directorios críticos del sistema",
			})
		} else {
			// Eliminar el directorio
			delete(fs.directories, absolutePath)
		}
	}

	return errors
}

// processTouch maneja el comando touch
func (fs *FileSystemState) processTouch(cmd models.CommandAST) []models.FileSystemError {
	var errors []models.FileSystemError

	if len(cmd.Arguments) == 0 {
		errors = append(errors, models.FileSystemError{
			Type:        "missing_argument",
			Command:     cmd.Raw,
			Line:        cmd.Line,
			Description: "touch requiere al menos un nombre de archivo",
			Suggestion:  "Especifique el nombre del archivo: touch nombre_archivo",
		})
		return errors
	}

	for _, arg := range cmd.Arguments {
		absolutePath := fs.resolvePath(arg)

		// Verificar si el directorio padre existe
		parentDir := filepath.Dir(absolutePath)
		if !fs.directories[parentDir] {
			errors = append(errors, models.FileSystemError{
				Type:        "parent_directory_not_found",
				Command:     cmd.Raw,
				Line:        cmd.Line,
				Path:        parentDir,
				Description: "No se puede crear el archivo '" + arg + "': el directorio padre no existe",
				Suggestion:  "Primero cree el directorio padre con: mkdir " + filepath.Dir(arg),
				MissingDependency: &models.MissingDependency{
					Type:     "directory",
					Name:     filepath.Dir(arg),
					Required: "mkdir " + filepath.Dir(arg),
				},
			})
		} else {
			// Crear el archivo
			fs.files[absolutePath] = true
		}
	}

	return errors
}

// processRm maneja el comando rm
func (fs *FileSystemState) processRm(cmd models.CommandAST) []models.FileSystemError {
	var errors []models.FileSystemError

	if len(cmd.Arguments) == 0 {
		errors = append(errors, models.FileSystemError{
			Type:        "missing_argument",
			Command:     cmd.Raw,
			Line:        cmd.Line,
			Description: "rm requiere al menos un nombre de archivo",
			Suggestion:  "Especifique el archivo a eliminar: rm nombre_archivo",
		})
		return errors
	}

	isRecursive := cmd.Flags["r"] != "" || cmd.Flags["rf"] != "" || cmd.Flags["R"] != ""

	for _, arg := range cmd.Arguments {
		absolutePath := fs.resolvePath(arg)

		// Si es un directorio y no tiene -r
		if fs.directories[absolutePath] && !isRecursive {
			errors = append(errors, models.FileSystemError{
				Type:        "directory_without_recursive",
				Command:     cmd.Raw,
				Line:        cmd.Line,
				Path:        absolutePath,
				Description: "No se puede eliminar '" + arg + "': es un directorio",
				Suggestion:  "Use rm -r para eliminar directorios o rmdir para directorios vacíos",
			})
		} else if !fs.files[absolutePath] && !fs.directories[absolutePath] {
			errors = append(errors, models.FileSystemError{
				Type:        "file_not_found",
				Command:     cmd.Raw,
				Line:        cmd.Line,
				Path:        absolutePath,
				Description: "No se puede eliminar '" + arg + "': archivo o directorio no encontrado",
				Suggestion:  "Verifique que el archivo exista antes de intentar eliminarlo",
			})
		} else {
			// Eliminar archivo o directorio
			if fs.files[absolutePath] {
				delete(fs.files, absolutePath)
			}
			if fs.directories[absolutePath] && isRecursive {
				delete(fs.directories, absolutePath)
			}
		}
	}

	return errors
}

// processCp maneja el comando cp
func (fs *FileSystemState) processCp(cmd models.CommandAST) []models.FileSystemError {
	var errors []models.FileSystemError

	if len(cmd.Arguments) < 2 {
		errors = append(errors, models.FileSystemError{
			Type:        "missing_argument",
			Command:     cmd.Raw,
			Line:        cmd.Line,
			Description: "cp requiere origen y destino",
			Suggestion:  "Use: cp archivo_origen archivo_destino",
		})
		return errors
	}

	source := cmd.Arguments[0]
	dest := cmd.Arguments[1]

	sourceAbsolute := fs.resolvePath(source)
	destAbsolute := fs.resolvePath(dest)

	// Verificar que el archivo origen existe
	if !fs.files[sourceAbsolute] && !fs.directories[sourceAbsolute] {
		errors = append(errors, models.FileSystemError{
			Type:        "file_not_found",
			Command:     cmd.Raw,
			Line:        cmd.Line,
			Path:        sourceAbsolute,
			Description: "No se puede copiar '" + source + "': archivo no encontrado",
			Suggestion:  "Verifique que el archivo origen exista",
			MissingDependency: &models.MissingDependency{
				Type:     "file",
				Name:     source,
				Required: "touch " + source,
			},
		})
	} else {
		// Verificar que el directorio destino existe
		destDir := filepath.Dir(destAbsolute)
		if !fs.directories[destDir] {
			errors = append(errors, models.FileSystemError{
				Type:        "parent_directory_not_found",
				Command:     cmd.Raw,
				Line:        cmd.Line,
				Path:        destDir,
				Description: "No se puede copiar a '" + dest + "': el directorio padre no existe",
				Suggestion:  "Primero cree el directorio: mkdir " + filepath.Dir(dest),
				MissingDependency: &models.MissingDependency{
					Type:     "directory",
					Name:     filepath.Dir(dest),
					Required: "mkdir " + filepath.Dir(dest),
				},
			})
		} else {
			// Crear el archivo destino
			if fs.files[sourceAbsolute] {
				fs.files[destAbsolute] = true
			}
		}
	}

	return errors
}

// processMv maneja el comando mv
func (fs *FileSystemState) processMv(cmd models.CommandAST) []models.FileSystemError {
	var errors []models.FileSystemError

	if len(cmd.Arguments) < 2 {
		errors = append(errors, models.FileSystemError{
			Type:        "missing_argument",
			Command:     cmd.Raw,
			Line:        cmd.Line,
			Description: "mv requiere origen y destino",
			Suggestion:  "Use: mv archivo_origen archivo_destino",
		})
		return errors
	}

	source := cmd.Arguments[0]
	dest := cmd.Arguments[1]

	sourceAbsolute := fs.resolvePath(source)
	destAbsolute := fs.resolvePath(dest)

	// Verificar que el archivo origen existe
	if !fs.files[sourceAbsolute] && !fs.directories[sourceAbsolute] {
		errors = append(errors, models.FileSystemError{
			Type:        "file_not_found",
			Command:     cmd.Raw,
			Line:        cmd.Line,
			Path:        sourceAbsolute,
			Description: "No se puede mover '" + source + "': archivo no encontrado",
			Suggestion:  "Verifique que el archivo origen exista",
			MissingDependency: &models.MissingDependency{
				Type:     "file",
				Name:     source,
				Required: "touch " + source,
			},
		})
	} else {
		// Verificar que el directorio destino existe
		destDir := filepath.Dir(destAbsolute)
		if !fs.directories[destDir] {
			errors = append(errors, models.FileSystemError{
				Type:        "parent_directory_not_found",
				Command:     cmd.Raw,
				Line:        cmd.Line,
				Path:        destDir,
				Description: "No se puede mover a '" + dest + "': el directorio padre no existe",
				Suggestion:  "Primero cree el directorio: mkdir " + filepath.Dir(dest),
				MissingDependency: &models.MissingDependency{
					Type:     "directory",
					Name:     filepath.Dir(dest),
					Required: "mkdir " + filepath.Dir(dest),
				},
			})
		} else {
			// Mover archivo: eliminar del origen y crear en destino
			if fs.files[sourceAbsolute] {
				delete(fs.files, sourceAbsolute)
				fs.files[destAbsolute] = true
			}
			if fs.directories[sourceAbsolute] {
				delete(fs.directories, sourceAbsolute)
				fs.directories[destAbsolute] = true
			}
		}
	}

	return errors
}

// processFileRead maneja comandos que leen archivos
func (fs *FileSystemState) processFileRead(cmd models.CommandAST) []models.FileSystemError {
	var errors []models.FileSystemError

	if len(cmd.Arguments) == 0 {
		// Algunos comandos pueden leer de stdin
		return errors
	}

	for _, arg := range cmd.Arguments {
		// Saltar flags y opciones
		if strings.HasPrefix(arg, "-") {
			continue
		}

		absolutePath := fs.resolvePath(arg)

		if !fs.files[absolutePath] && !fs.directories[absolutePath] {
			errors = append(errors, models.FileSystemError{
				Type:        "file_not_found",
				Command:     cmd.Raw,
				Line:        cmd.Line,
				Path:        absolutePath,
				Description: "No se puede leer '" + arg + "': archivo no encontrado",
				Suggestion:  "Verifique que el archivo exista o créelo con: touch " + arg,
				MissingDependency: &models.MissingDependency{
					Type:     "file",
					Name:     arg,
					Required: "touch " + arg,
				},
			})
		}
	}

	return errors
}

// resolvePath convierte una ruta relativa en absoluta
func (fs *FileSystemState) resolvePath(path string) string {
	if strings.HasPrefix(path, "/") {
		// Ruta absoluta
		return filepath.Clean(path)
	}

	if path == "~" {
		return "/home/user"
	}

	if strings.HasPrefix(path, "~/") {
		return filepath.Clean("/home/user/" + path[2:])
	}

	if path == "." {
		return fs.currentDirectory
	}

	if path == ".." {
		return filepath.Dir(fs.currentDirectory)
	}

	// Ruta relativa
	return filepath.Clean(fs.currentDirectory + "/" + path)
}

// GetCurrentState retorna información sobre el estado actual
func (fs *FileSystemState) GetCurrentState() models.FileSystemStateInfo {
	return models.FileSystemStateInfo{
		CurrentDirectory: fs.currentDirectory,
		DirectoryCount:   len(fs.directories),
		FileCount:        len(fs.files),
		CreatedDirs:      fs.getCreatedDirectories(),
		CreatedFiles:     fs.getCreatedFiles(),
	}
}

// getCreatedDirectories retorna solo los directorios creados por el usuario
func (fs *FileSystemState) getCreatedDirectories() []string {
	var created []string
	for dir := range fs.directories {
		if !fs.initialDirs[dir] {
			created = append(created, dir)
		}
	}
	return created
}

// getCreatedFiles retorna todos los archivos creados
func (fs *FileSystemState) getCreatedFiles() []string {
	var created []string
	for file := range fs.files {
		created = append(created, file)
	}
	return created
}
