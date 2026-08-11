package packets

import (
	"fmt"

	"github.com/bldsoft/mpegenc/internal/go-astits"
)

// PATCollector reconstructs and parses PAT sections for one requested program.
// Once that program appears in a current PAT, it returns the PID on which the
// corresponding PMT is carried.
type PATCollector struct {
	programNumber uint16
	sections      psiSectionCollector
}

func NewPATCollector(programNumber uint16) *PATCollector {
	return &PATCollector{programNumber: programNumber}
}

// Consume adds one PAT PID payload. PAT might be splitted into multiple packets. When a complete PAT section contains the
// requested program, it returns that program's PMT PID.
func (c *PATCollector) Consume(pusi bool, payload []byte) (uint16, bool, error) {
	sections, err := c.sections.Consume(pusi, payload)
	if err != nil {
		return 0, false, err
	}

	for _, section := range sections {
		if pmtPID, found, err := c.parseSection(section); err != nil || found {
			return pmtPID, found, err
		}
	}
	return 0, false, nil
}

func (c *PATCollector) parseSection(section []byte) (uint16, bool, error) {
	psiSection, err := astits.ParsePSISection(section)
	if err != nil {
		return 0, false, fmt.Errorf("parse PAT PSI section: %w", err)
	}
	if psiSection.Header.TableID != astits.PSITableIDPAT ||
		psiSection.Syntax == nil ||
		psiSection.Syntax.Header == nil ||
		psiSection.Syntax.Data == nil ||
		psiSection.Syntax.Data.PAT == nil {
		return 0, false, fmt.Errorf("PSI section is not a PAT")
	}
	if !psiSection.Syntax.Header.CurrentNextIndicator {
		return 0, false, nil
	}

	// go-astits validates the CRC for us
	for _, program := range psiSection.Syntax.Data.PAT.Programs {
		if program.ProgramNumber != c.programNumber {
			continue
		}
		return program.ProgramMapID, true, nil
	}
	return 0, false, nil
}
