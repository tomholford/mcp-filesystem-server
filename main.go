package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type FileInfo struct {
	Size        int64     `json:"size"`
	Created     time.Time `json:"created"`
	Modified    time.Time `json:"modified"`
	Accessed    time.Time `json:"accessed"`
	IsDirectory bool      `json:"isDirectory"`
	IsFile      bool      `json:"isFile"`
	Permissions string    `json:"permissions"`
}

type FilesystemServer struct {
	allowedDirs []string
	server      server.MCPServer
}

func NewFilesystemServer(allowedDirs []string) (*FilesystemServer, error) {
	// Normalize and validate directories
	normalized := make([]string, 0, len(allowedDirs))
	for _, dir := range allowedDirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve path %s: %w", dir, err)
		}

		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to access directory %s: %w",
				abs,
				err,
			)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("path is not a directory: %s", abs)
		}

		normalized = append(normalized, filepath.Clean(strings.ToLower(abs)))
	}

	s := &FilesystemServer{
		allowedDirs: normalized,
		server: server.NewDefaultServer(
			"secure-filesystem-server",
			"0.2.0",
		),
	}

	// Register tool handlers
	s.server.HandleInitialize(s.handleInitialize)
	s.server.HandleCallTool(s.handleToolCall)
	s.server.HandleListTools(s.handleListTools)

	return s, nil
}

func (s *FilesystemServer) validatePath(requestedPath string) (string, error) {
	abs, err := filepath.Abs(requestedPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	normalized := filepath.Clean(strings.ToLower(abs))

	// Check if path is within allowed directories
	allowed := false
	for _, dir := range s.allowedDirs {
		if strings.HasPrefix(normalized, dir) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf(
			"access denied - path outside allowed directories: %s",
			abs,
		)
	}

	// Handle symlinks
	realPath, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		// For new files, check parent directory
		parent := filepath.Dir(abs)
		realParent, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return "", fmt.Errorf("parent directory does not exist: %s", parent)
		}
		normalizedParent := filepath.Clean(strings.ToLower(realParent))
		for _, dir := range s.allowedDirs {
			if strings.HasPrefix(normalizedParent, dir) {
				return abs, nil
			}
		}
		return "", fmt.Errorf(
			"access denied - parent directory outside allowed directories",
		)
	}

	normalizedReal := filepath.Clean(strings.ToLower(realPath))
	for _, dir := range s.allowedDirs {
		if strings.HasPrefix(normalizedReal, dir) {
			return realPath, nil
		}
	}
	return "", fmt.Errorf(
		"access denied - symlink target outside allowed directories",
	)
}

func (s *FilesystemServer) getFileStats(path string) (FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FileInfo{}, err
	}

	return FileInfo{
		Size:        info.Size(),
		Created:     info.ModTime(), // Note: ModTime used as birth time isn't always available
		Modified:    info.ModTime(),
		Accessed:    info.ModTime(), // Note: Access time isn't always available
		IsDirectory: info.IsDir(),
		IsFile:      !info.IsDir(),
		Permissions: fmt.Sprintf("%o", info.Mode().Perm()),
	}, nil
}

func (s *FilesystemServer) searchFiles(
	rootPath, pattern string,
) ([]string, error) {
	var results []string
	pattern = strings.ToLower(pattern)

	err := filepath.Walk(
		rootPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip errors and continue
			}

			// Try to validate path
			if _, err := s.validatePath(path); err != nil {
				return nil // Skip invalid paths
			}

			if strings.Contains(strings.ToLower(info.Name()), pattern) {
				results = append(results, path)
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (s *FilesystemServer) handleListTools(
	ctx context.Context,
	cursor *string,
) (*mcp.ListToolsResult, error) {
	return &mcp.ListToolsResult{
		Tools: []mcp.Tool{
			{
				Name: "read_file",
				Description: "Read the complete contents of a file from the file system. " +
					"Handles various text encodings and provides detailed error messages " +
					"if the file cannot be read. Use this tool when you need to examine " +
					"the contents of a single file. Only works within allowed directories.",
				InputSchema: mcp.ToolInputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"path": map[string]interface{}{
							"type":        "string",
							"description": "Path to the file to read",
						},
					},
				},
			},
			{
				Name: "read_multiple_files",
				Description: "Read the contents of multiple files simultaneously. This is more " +
					"efficient than reading files one by one when you need to analyze " +
					"or compare multiple files.",
				InputSchema: mcp.ToolInputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"paths": map[string]interface{}{
							"type": "array",
							"items": map[string]interface{}{
								"type": "string",
							},
							"description": "List of file paths to read",
						},
					},
				},
			},
			{
				Name: "write_file",
				Description: "Create a new file or overwrite an existing file with new content. " +
					"Use with caution as it will overwrite existing files without warning.",
				InputSchema: mcp.ToolInputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"path": map[string]interface{}{
							"type":        "string",
							"description": "Path where to write the file",
						},
						"content": map[string]interface{}{
							"type":        "string",
							"description": "Content to write to the file",
						},
					},
				},
			},
			{
				Name: "create_directory",
				Description: "Create a new directory or ensure a directory exists. " +
					"Can create multiple nested directories in one operation.",
				InputSchema: mcp.ToolInputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"path": map[string]interface{}{
							"type":        "string",
							"description": "Path of the directory to create",
						},
					},
				},
			},
			{
				Name: "list_directory",
				Description: "Get a detailed listing of all files and directories in a specified path. " +
					"Results clearly distinguish between files and directories with [FILE] and [DIR] prefixes.",
				InputSchema: mcp.ToolInputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"path": map[string]interface{}{
							"type":        "string",
							"description": "Path of the directory to list",
						},
					},
				},
			},
			{
				Name: "move_file",
				Description: "Move or rename files and directories. Can move files between directories " +
					"and rename them in a single operation.",
				InputSchema: mcp.ToolInputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"source": map[string]interface{}{
							"type":        "string",
							"description": "Source path of the file or directory",
						},
						"destination": map[string]interface{}{
							"type":        "string",
							"description": "Destination path",
						},
					},
				},
			},
			{
				Name: "search_files",
				Description: "Recursively search for files and directories matching a pattern. " +
					"Searches through all subdirectories from the starting path.",
				InputSchema: mcp.ToolInputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"path": map[string]interface{}{
							"type":        "string",
							"description": "Starting path for the search",
						},
						"pattern": map[string]interface{}{
							"type":        "string",
							"description": "Search pattern to match against file names",
						},
					},
				},
			},
			{
				Name: "get_file_info",
				Description: "Retrieve detailed metadata about a file or directory including size, " +
					"creation time, last modified time, permissions, and type.",
				InputSchema: mcp.ToolInputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"path": map[string]interface{}{
							"type":        "string",
							"description": "Path to the file or directory",
						},
					},
				},
			},
			{
				Name:        "list_allowed_directories",
				Description: "Returns the list of directories that this server is allowed to access.",
				InputSchema: mcp.ToolInputSchema{
					Type:       "object",
					Properties: map[string]interface{}{},
				},
			},
		},
	}, nil
}

func (s *FilesystemServer) handleInitialize(
	ctx context.Context,
	capabilities mcp.ClientCapabilities,
	clientInfo mcp.Implementation,
	protocolVersion string,
) (*mcp.InitializeResult, error) {
	return &mcp.InitializeResult{
		ServerInfo: mcp.Implementation{
			Name:    "secure-filesystem-server",
			Version: "0.2.0",
		},
		ProtocolVersion: "2024-11-05",
		Capabilities: mcp.ServerCapabilities{
			Tools: &struct {
				ListChanged bool `json:"listChanged"`
			}{
				ListChanged: true,
			},
		},
		Instructions: fmt.Sprintf(
			"This server provides filesystem operations within the following directories:\n%s\n\n"+
				"Available tools include:\n"+
				"- read_file: Read file contents\n"+
				"- write_file: Write or create files\n"+
				"- list_directory: List directory contents\n"+
				"- create_directory: Create new directories\n"+
				"- move_file: Move or rename files\n"+
				"- search_files: Search for files by pattern\n"+
				"- get_file_info: Get file metadata\n"+
				"- list_allowed_directories: List allowed paths\n\n"+
				"All paths must be within the allowed directories for security.",
			strings.Join(s.allowedDirs, "\n"),
		),
	}, nil
}

func (s *FilesystemServer) handleToolCall(
	ctx context.Context,
	name string,
	args map[string]interface{},
) (*mcp.CallToolResult, error) {
	switch name {
	case "read_file":
		path, ok := args["path"].(string)
		if !ok {
			return nil, fmt.Errorf("path must be a string")
		}

		validPath, err := s.validatePath(path)
		if err != nil {
			return nil, err
		}

		content, err := os.ReadFile(validPath)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.TextContent{
						Type: "text",
						Text: fmt.Sprintf("Error reading file: %v", err),
					},
				},
				IsError: true,
			}, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: string(content),
				},
			},
		}, nil

	case "read_multiple_files":
		paths, ok := args["paths"].([]interface{})
		if !ok {
			return nil, fmt.Errorf("paths must be an array of strings")
		}

		var result strings.Builder
		for i, p := range paths {
			path, ok := p.(string)
			if !ok {
				return nil, fmt.Errorf("path must be a string")
			}

			if i > 0 {
				result.WriteString("\n---\n")
			}

			validPath, err := s.validatePath(path)
			if err != nil {
				fmt.Fprintf(&result, "%s: Error - %v\n", path, err)
				continue
			}

			content, err := os.ReadFile(validPath)
			if err != nil {
				fmt.Fprintf(&result, "%s: Error - %v\n", path, err)
				continue
			}

			fmt.Fprintf(&result, "%s:\n%s", path, string(content))
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: result.String(),
				},
			},
		}, nil

	case "write_file":
		path, ok := args["path"].(string)
		if !ok {
			return nil, fmt.Errorf("path must be a string")
		}
		content, ok := args["content"].(string)
		if !ok {
			return nil, fmt.Errorf("content must be a string")
		}

		validPath, err := s.validatePath(path)
		if err != nil {
			return nil, err
		}

		if err := os.WriteFile(validPath, []byte(content), 0644); err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.TextContent{
						Type: "text",
						Text: fmt.Sprintf("Error writing file: %v", err),
					},
				},
				IsError: true,
			}, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("Successfully wrote to %s", path),
				},
			},
		}, nil

	case "create_directory":
		path, ok := args["path"].(string)
		if !ok {
			return nil, fmt.Errorf("path must be a string")
		}

		validPath, err := s.validatePath(path)
		if err != nil {
			return nil, err
		}

		if err := os.MkdirAll(validPath, 0755); err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.TextContent{
						Type: "text",
						Text: fmt.Sprintf("Error creating directory: %v", err),
					},
				},
				IsError: true,
			}, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf(
						"Successfully created directory %s",
						path,
					),
				},
			},
		}, nil

	case "list_directory":
		path, ok := args["path"].(string)
		if !ok {
			return nil, fmt.Errorf("path must be a string")
		}

		validPath, err := s.validatePath(path)
		if err != nil {
			return nil, err
		}

		entries, err := os.ReadDir(validPath)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.TextContent{
						Type: "text",
						Text: fmt.Sprintf("Error reading directory: %v", err),
					},
				},
				IsError: true,
			}, nil
		}

		var result strings.Builder
		for _, entry := range entries {
			prefix := "[FILE]"
			if entry.IsDir() {
				prefix = "[DIR]"
			}
			fmt.Fprintf(&result, "%s %s\n", prefix, entry.Name())
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: result.String(),
				},
			},
		}, nil

	case "move_file":
		source, ok := args["source"].(string)
		if !ok {
			return nil, fmt.Errorf("source must be a string")
		}
		destination, ok := args["destination"].(string)
		if !ok {
			return nil, fmt.Errorf("destination must be a string")
		}

		validSource, err := s.validatePath(source)
		if err != nil {
			return nil, err
		}
		validDest, err := s.validatePath(destination)
		if err != nil {
			return nil, err
		}

		if err := os.Rename(validSource, validDest); err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.TextContent{
						Type: "text",
						Text: fmt.Sprintf("Error moving file: %v", err),
					},
				},
				IsError: true,
			}, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf(
						"Successfully moved %s to %s",
						source,
						destination,
					),
				},
			},
		}, nil

	case "search_files":
		path, ok := args["path"].(string)
		if !ok {
			return nil, fmt.Errorf("path must be a string")
		}
		pattern, ok := args["pattern"].(string)
		if !ok {
			return nil, fmt.Errorf("pattern must be a string")
		}

		validPath, err := s.validatePath(path)
		if err != nil {
			return nil, err
		}

		results, err := s.searchFiles(validPath, pattern)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.TextContent{
						Type: "text",
						Text: fmt.Sprintf("Error searching files: %v", err),
					},
				},
				IsError: true,
			}, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: strings.Join(results, "\n"),
				},
			},
		}, nil

	case "get_file_info":
		path, ok := args["path"].(string)
		if !ok {
			return nil, fmt.Errorf("path must be a string")
		}

		validPath, err := s.validatePath(path)
		if err != nil {
			return nil, err
		}

		info, err := s.getFileStats(validPath)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.TextContent{
						Type: "text",
						Text: fmt.Sprintf("Error getting file info: %v", err),
					},
				},
				IsError: true,
			}, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf(
						"Size: %d\nCreated: %s\nModified: %s\nAccessed: %s\nIsDirectory: %v\nIsFile: %v\nPermissions: %s",
						info.Size,
						info.Created.Format(time.RFC3339),
						info.Modified.Format(time.RFC3339),
						info.Accessed.Format(time.RFC3339),
						info.IsDirectory,
						info.IsFile,
						info.Permissions,
					),
				},
			},
		}, nil

	case "list_allowed_directories":
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf(
						"Allowed directories:\n%s",
						strings.Join(s.allowedDirs, "\n"),
					),
				},
			},
		}, nil

	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

func (s *FilesystemServer) Serve() error {
	return server.ServeStdio(s.server)
}

func main() {
	// Parse command line arguments
	if len(os.Args) < 2 {
		fmt.Fprintf(
			os.Stderr,
			"Usage: %s <allowed-directory> [additional-directories...]\n",
			os.Args[0],
		)
		os.Exit(1)
	}

	// Create and start the server
	fs, err := NewFilesystemServer(os.Args[1:])
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Serve requests
	if err := fs.Serve(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
