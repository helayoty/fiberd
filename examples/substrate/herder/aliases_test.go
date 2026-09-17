package herder

import ateompb "github.com/helayoty/fiberd/examples/substrate/proto/ateom"

// Short names for the generated types, so the tests read as the protocol.
type (
	ateompbRun       = ateompb.RunWorkloadRequest
	ateompbRestore   = ateompb.RestoreWorkloadRequest
	ateompbCkpt      = ateompb.CheckpointWorkloadRequest
	ateompbTerm      = ateompb.TerminateWorkloadRequest
	ateompbStatsReq  = ateompb.GetWorkloadStatsRequest
	ateompbActiveReq = ateompb.GetActiveWorkloadStatsRequest
	ateompbSpec      = ateompb.WorkloadSpec
	ateompbContainer = ateompb.Container
	ateompbReadyz    = ateompb.Readyz
	ateompbHTTPGet   = ateompb.HTTPGetAction
)

const (
	scopeFull         = ateompb.SnapshotScope_SNAPSHOT_SCOPE_FULL
	scopeData         = ateompb.SnapshotScope_SNAPSHOT_SCOPE_DATA
	scopeDataOnGolden = ateompb.SnapshotScope_SNAPSHOT_SCOPE_DATA_ON_GOLDEN
	noWorkload        = ateompb.NoSampleReason_NO_SAMPLE_REASON_NO_WORKLOAD
)
