//go:build ignore

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

var sensitiveFieldNames = map[string]bool{
	"Token":      true,
	"Secret":     true,
	"Password":   true,
	"Credential": true,
	"APIKey":     true,
}

var contextSensitiveFields = map[string]bool{
	"Key": true,
	"Raw": true,
}

var sensitiveTypePatterns = []string{
	"Token",
	"SVID",
	"Key",
	"Credential",
	"Secret",
}

type violation struct {
	file       string
	typeName   string
	field      string
	missingMethods []string
}

func main() {
	root := filepath.Join("internal")
	if _, err := os.Stat(root); err != nil {
		fmt.Fprintf(os.Stderr, "opening internal/ directory: %v\n", err)
		os.Exit(1)
	}

	var violations []violation

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fileViolations, err := checkFile(path)
		if err != nil {
			return fmt.Errorf("checking %s: %w", path, err)
		}
		violations = append(violations, fileViolations...)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "walking source tree: %v\n", err)
		os.Exit(1)
	}

	if len(violations) > 0 {
		fmt.Println("SECRET REDACTION VIOLATIONS:")
		fmt.Println()
		for _, v := range violations {
			fmt.Printf("  %s: type %s has sensitive field %q but is missing: %s\n",
				v.file, v.typeName, v.field, strings.Join(v.missingMethods, ", "))
		}
		fmt.Printf("\n%d violation(s) found. Types with sensitive fields must implement String() and MarshalJSON() with redaction.\n", len(violations))
		os.Exit(1)
	}

	fmt.Println("SECRET REDACTION CHECK PASSED: all types with sensitive fields implement String() and MarshalJSON().")
}

func checkFile(path string) ([]violation, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	sensitiveTypes := findSensitiveTypes(file)
	if len(sensitiveTypes) == 0 {
		return nil, nil
	}

	methods := findMethodsOnTypes(file)

	var violations []violation
	for typeName, fieldName := range sensitiveTypes {
		var missing []string
		if !methods[typeName+".String"] {
			missing = append(missing, "String()")
		}
		if !methods[typeName+".MarshalJSON"] {
			missing = append(missing, "MarshalJSON()")
		}
		if len(missing) > 0 {
			violations = append(violations, violation{
				file:           path,
				typeName:       typeName,
				field:          fieldName,
				missingMethods: missing,
			})
		}
	}

	return violations, nil
}

func findSensitiveTypes(file *ast.File) map[string]string {
	result := make(map[string]string)

	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}

		typeName := ts.Name.Name
		for _, field := range st.Fields.List {
			for _, name := range field.Names {
				if sensitiveFieldNames[name.Name] {
					result[typeName] = name.Name
				}
				if contextSensitiveFields[name.Name] && typeNameIsSensitive(typeName) {
					result[typeName] = name.Name
				}
			}
		}
		return true
	})

	return result
}

func typeNameIsSensitive(name string) bool {
	for _, pattern := range sensitiveTypePatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

func findMethodsOnTypes(file *ast.File) map[string]bool {
	result := make(map[string]bool)

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}

		recvType := receiverTypeName(fn.Recv.List[0].Type)
		if recvType == "" {
			continue
		}

		result[recvType+"."+fn.Name.Name] = true
	}

	return result
}

func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name
		}
	}
	return ""
}
