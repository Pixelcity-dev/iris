package reporter

import (
	"encoding/xml"
	"fmt"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type JUnitReporter struct{}

func (r *JUnitReporter) Name() string {
	return "junit"
}

func (r *JUnitReporter) Extension() string {
	return "xml"
}

type JUnitOutput struct {
	XMLName    xml.Name         `xml:"testsuites"`
	TestSuites []JUnitTestSuite `xml:"testsuite"`
}

type JUnitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

type JUnitTestCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
}

type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

func (r *JUnitReporter) Generate(results []core.ScanResult, opts ReportOptions) ([]byte, error) {
	output := JUnitOutput{}

	for _, result := range results {
		suite := JUnitTestSuite{
			Name:      result.Scanner,
			Tests:     len(result.Findings),
			Failures:  0,
			Timestamp: time.Now().Format(time.RFC3339),
		}

		for _, f := range result.Findings {
			testCase := JUnitTestCase{
				Name:      f.Title,
				Classname: f.RuleID,
				Time:      fmt.Sprintf("%.3f", result.Duration),
			}

			if f.Severity >= core.SeverityHigh {
				suite.Failures++
				testCase.Failure = &JUnitFailure{
					Message: fmt.Sprintf("[%s] %s", f.Severity.String(), f.Description),
					Type:    f.Category,
					Content: f.Description,
				}
			}

			suite.TestCases = append(suite.TestCases, testCase)
		}

		output.TestSuites = append(output.TestSuites, suite)
	}

	return xml.MarshalIndent(output, "", "  ")
}
