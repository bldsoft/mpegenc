package packets

import (
	"fmt"

	"github.com/bldsoft/mpegenc/internal/go-astits"
)

// PMTCollector reconstructs and parses PMT sections for one requested program.
type PMTCollector struct {
	programNumber uint16
	sections      psiSectionCollector
}

func NewPMTCollector(programNumber uint16) *PMTCollector {
	return &PMTCollector{programNumber: programNumber}
}

// Consume adds one PMT PID payload. Once a complete PMT section for the
// requested program arrives, it returns the parsed section.
func (c *PMTCollector) Consume(pusi bool, payload []byte) (*astits.PSISection, bool, error) {
	sections, err := c.sections.Consume(pusi, payload)
	if err != nil {
		return nil, false, err
	}

	for _, section := range sections {
		psiSection, err := astits.ParsePSISection(section)
		if err != nil {
			return nil, false, fmt.Errorf("parse PMT PSI section: %w", err)
		}
		if psiSection.Header.TableID != astits.PSITableIDPMT ||
			psiSection.Syntax == nil ||
			psiSection.Syntax.Header == nil ||
			psiSection.Syntax.Data == nil ||
			psiSection.Syntax.Data.PMT == nil {
			return nil, false, fmt.Errorf("PSI section is not a PMT")
		}
		if !psiSection.Syntax.Header.CurrentNextIndicator {
			continue
		}

		pmt := psiSection.Syntax.Data.PMT
		if pmt.ProgramNumber == c.programNumber {
			return psiSection, true, nil
		}
	}
	return nil, false, nil
}
