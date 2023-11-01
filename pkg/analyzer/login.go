package analyzer

import (
	"fmt"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
)

type LoginAnalyzer struct{}

func (LoginAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) { // [AMR]: Interface implementation for Pod

	kind := "Login"

	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})

	var preAnalysis = map[string]common.PreAnalysis{}

	var failures []common.Failure
	////////////////////////////////////////
	//   Analyze failing login attempts   //
	////////////////////////////////////////

	failures = append(failures, common.Failure{
		Text:      "node under brute-force login attack",
		Sensitive: []common.Sensitive{},
	})

	////////////////////////////////////////

	if len(failures) > 0 {
		preAnalysis[fmt.Sprintf("%s/%s", "error-details", "num-failed-login")] = common.PreAnalysis{
			//Pod:            pod,
			FailureDetails: failures,
		}
		//AnalyzerErrorsMetric.WithLabelValues(kind, pod.Name, pod.Namespace).Set(float64(len(failures)))
	}

	for key, value := range preAnalysis {
		var currentAnalysis = common.Result{
			Kind:  kind,
			Name:  key,
			Error: value.FailureDetails,
		}

		a.Results = append(a.Results, currentAnalysis)
	}

	return a.Results, nil
}
