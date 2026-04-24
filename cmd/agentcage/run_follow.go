package main

import (
	"context"
	"fmt"
	"os"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"google.golang.org/grpc"
)

const (
	followMaxConsecutiveErrors = 20
	followBaseBackoff          = 3 * time.Second
	followMaxBackoff           = 30 * time.Second
	followPollInterval         = 3 * time.Second
	followStaleTimeout         = 30 * time.Minute
	followHardTimeout          = 5 * time.Hour
)

func followAssessment(parentCtx context.Context, conn *grpc.ClientConn, assessmentID, format string) {
	ctx, cancel := context.WithTimeout(parentCtx, followHardTimeout)
	defer cancel()

	client := pb.NewAssessmentServiceClient(conn)
	jsonMode := format == "json"
	var lastStatus string
	var lastValidated int32 = -1
	var lastCandidate int32 = -1
	var lastCages int32 = -1
	var consecutiveErrors int
	lastChange := time.Now()

	fmt.Println("\nFollowing assessment progress... (Ctrl+C to detach, assessment continues)")

	for {
		pollCtx, pollCancel := context.WithTimeout(ctx, 5*time.Second)
		resp, err := client.GetAssessment(pollCtx, &pb.GetAssessmentRequest{AssessmentId: assessmentID})
		pollCancel()

		if ctx.Err() != nil {
			printDetachMessage(assessmentID)
			return
		}

		if err != nil {
			consecutiveErrors++
			fmt.Fprintf(os.Stderr, "  poll error (%d/%d): %v\n", consecutiveErrors, followMaxConsecutiveErrors, err)
			if consecutiveErrors >= followMaxConsecutiveErrors {
				fmt.Fprintf(os.Stderr, "\nToo many consecutive poll errors. Detaching.\n")
				fmt.Fprintf(os.Stderr, "Run 'agentcage assessments --id %s' to check progress.\n", assessmentID)
				return
			}
			backoff := min(followBaseBackoff*time.Duration(1<<min(consecutiveErrors-1, 4)), followMaxBackoff)
			if !sleepCtx(ctx, backoff) {
				printDetachMessage(assessmentID)
				return
			}
			continue
		}
		consecutiveErrors = 0

		info := resp.GetAssessment()
		status := info.GetStatus().String()
		stats := info.GetStats()

		if status != lastStatus {
			if jsonMode {
				fmt.Printf("{\"phase\":%q,\"assessment_id\":%q}\n", status, assessmentID)
			} else {
				fmt.Printf("  Phase: %s\n", status)
			}
			lastStatus = status
			lastChange = time.Now()
		}

		if stats != nil {
			if stats.GetActiveCages() != lastCages {
				lastCages = stats.GetActiveCages()
				lastChange = time.Now()
				if !jsonMode {
					fmt.Printf("  Cages: %d active, %d total\n", lastCages, stats.GetTotalCages())
				}
			}

			validated := stats.GetFindingsValidated()
			candidate := stats.GetFindingsCandidate()
			if validated != lastValidated || candidate != lastCandidate {
				if jsonMode {
					fmt.Printf("{\"findings_candidate\":%d,\"findings_validated\":%d,\"findings_rejected\":%d,\"tokens_consumed\":%d}\n",
						candidate, validated, stats.GetFindingsRejected(), stats.GetTokensConsumed())
				} else {
					fmt.Printf("  Findings: %d candidate, %d validated, %d rejected\n",
						candidate, validated, stats.GetFindingsRejected())
				}
				lastValidated = validated
				lastCandidate = candidate
				lastChange = time.Now()
			}
		}

		switch info.GetStatus() {
		case pb.AssessmentStatus_ASSESSMENT_STATUS_APPROVED:
			var v int32
			if stats != nil {
				v = stats.GetFindingsValidated()
			}
			if jsonMode {
				fmt.Printf("{\"result\":\"approved\",\"findings_validated\":%d}\n", v)
			} else {
				fmt.Printf("\nAssessment approved. %d validated findings.\n", v)
				fmt.Printf("Run 'agentcage report --assessment %s' for full report.\n", assessmentID)
			}
			return
		case pb.AssessmentStatus_ASSESSMENT_STATUS_REJECTED:
			if jsonMode {
				fmt.Printf("{\"result\":\"rejected\"}\n")
			} else {
				fmt.Printf("\nAssessment rejected.\n")
				fmt.Printf("Run 'agentcage report --assessment %s' for details.\n", assessmentID)
			}
			return
		case pb.AssessmentStatus_ASSESSMENT_STATUS_FAILED:
			if jsonMode {
				fmt.Printf("{\"result\":\"failed\"}\n")
			} else {
				fmt.Printf("\nAssessment failed.\n")
				fmt.Printf("Run 'agentcage logs --assessment %s' for details.\n", assessmentID)
			}
			return
		case pb.AssessmentStatus_ASSESSMENT_STATUS_PENDING_REVIEW:
			if jsonMode {
				fmt.Printf("{\"result\":\"pending_review\",\"assessment_id\":%q}\n", assessmentID)
			} else {
				fmt.Printf("\nAssessment awaiting human review.\n")
				fmt.Printf("Run 'agentcage interventions' to see pending decisions.\n")
			}
			return
		case pb.AssessmentStatus_ASSESSMENT_STATUS_UNSPECIFIED:
			if jsonMode {
				fmt.Printf("{\"result\":\"error\",\"detail\":\"server returned unspecified status\"}\n")
			} else {
				fmt.Fprintf(os.Stderr, "\nServer returned unspecified status for assessment %s.\n", assessmentID)
				fmt.Fprintf(os.Stderr, "Run 'agentcage assessments --id %s' to check progress.\n", assessmentID)
			}
			return
		}

		if time.Since(lastChange) > followStaleTimeout {
			fmt.Fprintf(os.Stderr, "\nNo status change for %s. Detaching.\n", followStaleTimeout)
			fmt.Fprintf(os.Stderr, "Assessment %s may be stuck in %s. Check 'agentcage interventions' for pending decisions.\n", assessmentID, lastStatus)
			fmt.Fprintf(os.Stderr, "Run 'agentcage assessments --id %s' to check progress.\n", assessmentID)
			return
		}

		if !sleepCtx(ctx, followPollInterval) {
			printDetachMessage(assessmentID)
			return
		}
	}
}

func printDetachMessage(assessmentID string) {
	fmt.Printf("\nDetached. Assessment %s continues on the server.\n", assessmentID)
	fmt.Printf("Run 'agentcage assessments --id %s' to check progress.\n", assessmentID)
}

// Returns false if the context was cancelled during the sleep.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
