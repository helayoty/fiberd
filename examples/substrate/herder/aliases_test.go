package herder

import ateompb "github.com/helayoty/fiberd/examples/substrate/proto/ateom"

// Short names for the generated types, so the tests read as the protocol.
type (
	ateompbRun         = ateompb.RunWorkloadRequest
	ateompbRestore     = ateompb.RestoreWorkloadRequest
	ateompbCkpt        = ateompb.CheckpointWorkloadRequest
	ateompbTerm        = ateompb.TerminateWorkloadRequest
	ateompbStatsReq    = ateompb.GetWorkloadStatsRequest
	ateompbActiveReq   = ateompb.GetActiveWorkloadStatsRequest
	ateompbSpec        = ateompb.WorkloadSpec
	ateompbContainer   = ateompb.Container
	ateompbWakeup      = ateompb.WakeupProbe
	ateompbHTTPGet     = ateompb.HttpGetAction
	ateompbActorDirs   = ateompb.ActorDirs
	ateompbStatsSample = ateompb.WorkloadStatsSample
)

const (
	fidelityMemory  = ateompb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY
	fidelityVolumes = ateompb.SnapshotFidelity_SNAPSHOT_FIDELITY_VOLUMES
	fidelityRootfs  = ateompb.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS
	sourceCgroup    = ateompb.StatsSource_STATS_SOURCE_CGROUP
)
