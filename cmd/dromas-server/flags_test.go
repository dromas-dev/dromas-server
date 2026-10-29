package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every command takes its options as --name alone: one dash and a long name
// is read as a run of shorthands, and no option has one, so each is refused
// before anything starts.
func TestAOneDashLongFlagIsRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		run  func() error
	}{
		{"serve -dev", func() error { return serve([]string{"-dev", "--listen", "127.0.0.1:0"}) }},
		{"serve -listen", func() error { return serve([]string{"--dev", "-listen", "127.0.0.1:0"}) }},
		{"account create -accounts-table", func() error { return account("create", []string{"-accounts-table", "t"}) }},
		{"limits clear -socket", func() error { return limits("clear", []string{"-socket", "s", "--ip", "192.0.2.1"}) }},
		{"limits top -count", func() error {
			return limits("top", []string{"--socket", "s", "--limit", "registrations", "-count", "1"})
		}},
	} {
		done := make(chan error, 1)
		go func() { done <- c.run() }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "unknown shorthand flag") {
				t.Errorf("%s: %v, want it refused as an unknown shorthand", c.name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: started", c.name)
		}
	}
}

// No option has a shorthand: the commands' sources call none of pflag's
// shorthand forms (StringP, IntVarP, ...), so --name is each option's only
// spelling.
func TestNoOptionHasAShorthand(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "fs" {
				checked++
				if strings.HasSuffix(sel.Sel.Name, "P") {
					t.Errorf("%s: fs.%s gives an option a shorthand", fset.Position(call.Pos()), sel.Sel.Name)
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no fs calls found: the check read nothing")
	}
}
