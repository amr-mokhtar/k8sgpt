package analyzer

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SecurityAnalyzer struct{}

var authMonitorWindow = 2 * time.Minute
var authErrThreshold = 5

func (SecurityAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) { // [AMR]: Interface implementation for Pod

	kind := "Security"

	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})

	list, err := a.Client.GetClient().CoreV1().Nodes().List(a.Context, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	node := list.Items[0]

	var preAnalysis = map[string]common.PreAnalysis{}

	var failures []common.Failure

	f, err := os.Open("/var/log/auth.log")
	if err != nil {
		fmt.Print("ERROR:", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	timeNow := time.Now()
	failingAttempts := 0

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Failed password") {
			if line[4] == ' ' {
				line = line[:4] + "0" + line[5:]
			}
			logline := strings.Split(line, " ")
			logTime, err := time.Parse(time.Stamp, string(logline[0]+" "+logline[1]+" "+logline[2]))
			if err != nil {
				panic(err)
			}
			logTime = time.Date(timeNow.Year(), logTime.Month(), logTime.Day(),
				logTime.Hour(), logTime.Minute(), logTime.Second(), logTime.Nanosecond(),
				logTime.Location())

			if timeNow.Sub(logTime) < authMonitorWindow {
				failingAttempts++
			}
		}
	}

	fmt.Println("--> failing logins:", failingAttempts)

	if failingAttempts > authErrThreshold {
		failures = append(failures, common.Failure{
			Text:      fmt.Sprintf("Detected multiple wrong password logins, %d failures in %s duration. Node is under brute force attack!!", failingAttempts, authMonitorWindow),
			Sensitive: []common.Sensitive{},
		})
	}

	if len(failures) > 0 {
		preAnalysis["bruteforceattack"] = common.PreAnalysis{
			Node:           node,
			FailureDetails: failures,
		}
		AnalyzerErrorsMetric.WithLabelValues(kind, node.Name, "").Set(float64(len(failures)))
	}

	for key, value := range preAnalysis {
		var currentAnalysis = common.Result{
			Kind:  kind,
			Name:  key,
			Error: value.FailureDetails,
		}

		parent, _ := util.GetParent(a.Client, value.Node.ObjectMeta)
		currentAnalysis.ParentObject = parent
		a.Results = append(a.Results, currentAnalysis)
	}

	return a.Results, nil
}
