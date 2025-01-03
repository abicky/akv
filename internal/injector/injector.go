package injector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	InjectionModeText = iota
	InjectionModeValue
)

type Injector struct {
	factory ClientFactory
	re      *regexp.Regexp
}

const baseRegexp = `akv://[^/]{3,24}/[-0-9A-Za-z]{1,127}`

func NewInjector(mode int, factory ClientFactory) (*Injector, error) {
	var exp string
	switch mode {
	case InjectionModeText:
		exp = `\b` + baseRegexp + `\b`
	case InjectionModeValue:
		exp = `\A` + baseRegexp + `\z`
	}

	return &Injector{
		factory: factory,
		re:      regexp.MustCompile(exp),
	}, nil
}

func (i *Injector) Inject(ctx context.Context, input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Split(scanLinesWithNewlines)
	for scanner.Scan() {
		var err error
		var client Client
		injected := i.re.ReplaceAllStringFunc(scanner.Text(), func(s string) string {
			if err != nil {
				return ""
			}

			parts := strings.Split(strings.TrimPrefix(s, "akv://"), "/")
			client, err = i.factory.NewClient(parts[0])
			if err != nil {
				err = fmt.Errorf("failed to initialize client: %w", err)
				return ""
			}

			resp, e := client.GetSecret(ctx, parts[1], "", nil)
			if e != nil {
				err = fmt.Errorf("failed to get secret: %w", e)
				return ""
			}
			return *resp.Value
		})
		if err != nil {
			return err
		}

		fmt.Fprint(output, injected)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	return nil
}

// This function is derived from bufio.ScanLines to keep newlines
func scanLinesWithNewlines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		// We have a full newline-terminated line.
		return i + 1, data[0 : i+1], nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}
