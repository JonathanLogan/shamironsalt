package flags

import (
	"bufio"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
)

// IniError contains location information on where an error occurred.
type IniError struct {
	// The error message.
	Message string

	// The filename of the file in which the error occurred.
	File string

	// The line number at which the error occurred.
	LineNumber uint
}

// Error provides a "file:line: message" formatted message of the ini error.
func (x *IniError) Error() string {
	return fmt.Sprintf(
		"%s:%d: %s",
		x.File,
		x.LineNumber,
		x.Message,
	)
}

// IniParser is a utility to read and write flags options from and to ini
// formatted strings.
type IniParser struct {
	ParseAsDefaults bool // override default flags

	parser *Parser
}

type iniValue struct {
	Name       string
	Value      string
	Quoted     bool
	LineNumber uint
}

type iniSection []iniValue

type ini struct {
	File     string
	Sections map[string]iniSection
}

// Parse parses flags from an ini format. You can use ParseFile as a
// convenience function to parse from a filename instead of a general
// io.Reader.
//
// The format of the ini file is as follows:
//
//     [Option group name]
//     option = value
//
// Each section in the ini file represents an option group or command in the
// flags parser. The default flags parser option group (i.e. when using
// flags.Parse) is named 'Application Options'. The ini option name is matched
// in the following order:
//
//     1. Compared to the ini-name tag on the option struct field (if present)
//     2. Compared to the struct field name
//     3. Compared to the option long name (if present)
//     4. Compared to the option short name (if present)
//
// Sections for nested groups and commands can be addressed using a dot `.'
// namespacing notation (i.e [subcommand.Options]). Group section names are
// matched case insensitive.
//
// The returned errors can be of the type flags.Error or flags.IniError.
func (i *IniParser) Parse(reader io.Reader) error {
	ini, err := readIni(reader, "")

	if err != nil {
		return err
	}

	return i.parse(ini)
}

func readFullLine(reader *bufio.Reader) (string, error) {
	var line []byte

	for {
		l, more, err := reader.ReadLine()

		if err != nil {
			return "", err
		}

		if line == nil && !more {
			return string(l), nil
		}

		line = append(line, l...)

		if !more {
			break
		}
	}

	return string(line), nil
}

func readIni(contents io.Reader, filename string) (*ini, error) {
	ret := &ini{
		File:     filename,
		Sections: make(map[string]iniSection),
	}

	reader := bufio.NewReader(contents)

	// Empty global section
	section := make(iniSection, 0, 10)
	sectionname := ""

	ret.Sections[sectionname] = section

	var lineno uint

	for {
		line, err := readFullLine(reader)

		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		lineno++
		line = strings.TrimSpace(line)

		// Skip empty lines and lines starting with ; (comments)
		if len(line) == 0 || line[0] == ';' || line[0] == '#' {
			continue
		}

		if line[0] == '[' {
			if line[0] != '[' || line[len(line)-1] != ']' {
				return nil, &IniError{
					Message:    "malformed section header",
					File:       filename,
					LineNumber: lineno,
				}
			}

			name := strings.TrimSpace(line[1 : len(line)-1])

			if len(name) == 0 {
				return nil, &IniError{
					Message:    "empty section name",
					File:       filename,
					LineNumber: lineno,
				}
			}

			sectionname = name
			section = ret.Sections[name]

			if section == nil {
				section = make(iniSection, 0, 10)
				ret.Sections[name] = section
			}

			continue
		}

		// Parse option here
		keyval := strings.SplitN(line, "=", 2)

		if len(keyval) != 2 {
			return nil, &IniError{
				Message:    fmt.Sprintf("malformed key=value (%s)", line),
				File:       filename,
				LineNumber: lineno,
			}
		}

		name := strings.TrimSpace(keyval[0])
		value := strings.TrimSpace(keyval[1])
		quoted := false

		if len(value) != 0 && value[0] == '"' {
			if v, err := strconv.Unquote(value); err == nil {
				value = v

				quoted = true
			} else {
				return nil, &IniError{
					Message:    err.Error(),
					File:       filename,
					LineNumber: lineno,
				}
			}
		}

		section = append(section, iniValue{
			Name:       name,
			Value:      value,
			Quoted:     quoted,
			LineNumber: lineno,
		})

		ret.Sections[sectionname] = section
	}

	return ret, nil
}

func (i *IniParser) matchingGroups(name string) []*Group {
	if len(name) == 0 {
		var ret []*Group

		i.parser.eachGroup(func(g *Group) {
			ret = append(ret, g)
		})

		return ret
	}

	g := i.parser.groupByName(name)

	if g != nil {
		return []*Group{g}
	}

	return nil
}

func (i *IniParser) parse(ini *ini) error {
	p := i.parser

	var quotesLookup = make(map[*Option]bool)

	for name, section := range ini.Sections {
		groups := i.matchingGroups(name)

		if len(groups) == 0 {
			return newErrorf(ErrUnknownGroup, "could not find option group `%s'", name)
		}

		for _, inival := range section {
			var opt *Option

			for _, group := range groups {
				opt = group.optionByName(inival.Name, func(o *Option, n string) bool {
					return strings.ToLower(o.tag.Get("ini-name")) == strings.ToLower(n)
				})

				if opt != nil && len(opt.tag.Get("no-ini")) != 0 {
					opt = nil
				}

				if opt != nil {
					break
				}
			}

			if opt == nil {
				if (p.Options & IgnoreUnknown) == None {
					return &IniError{
						Message:    fmt.Sprintf("unknown option: %s", inival.Name),
						File:       ini.File,
						LineNumber: inival.LineNumber,
					}
				}

				continue
			}

			// ini value is ignored if override is set and
			// value was previously set from non default
			if i.ParseAsDefaults && !opt.isSetDefault {
				continue
			}

			pval := &inival.Value

			if !opt.canArgument() && len(inival.Value) == 0 {
				pval = nil
			} else {
				if opt.value.Type().Kind() == reflect.Map {
					parts := strings.SplitN(inival.Value, ":", 2)

					// only handle unquoting
					if len(parts) == 2 && parts[1][0] == '"' {
						if v, err := strconv.Unquote(parts[1]); err == nil {
							parts[1] = v

							inival.Quoted = true
						} else {
							return &IniError{
								Message:    err.Error(),
								File:       ini.File,
								LineNumber: inival.LineNumber,
							}
						}

						s := parts[0] + ":" + parts[1]

						pval = &s
					}
				}
			}

			if err := opt.set(pval); err != nil {
				return &IniError{
					Message:    err.Error(),
					File:       ini.File,
					LineNumber: inival.LineNumber,
				}
			}

			// either all INI values are quoted or only values who need quoting
			if _, ok := quotesLookup[opt]; !inival.Quoted || !ok {
				quotesLookup[opt] = inival.Quoted
			}

			opt.tag.Set("_read-ini-name", inival.Name)
		}
	}

	for opt, quoted := range quotesLookup {
		opt.iniQuote = quoted
	}

	return nil
}
