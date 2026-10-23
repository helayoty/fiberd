package core

// DeviceReporter is implemented by runtimes that start device engines.
// fiberd serves its report as GET /device on the admin socket. since is
// the last event seq the caller has seen, 0 for every event held. A
// runtime that does not implement it has no engine to report.
type DeviceReporter interface {
	DeviceReport(since uint64) DeviceReport
}

// DeviceReport is the home's engines, sorted by grant, and its device
// events after a seq, oldest first. Neither list is nil, so both encode
// as [] when empty.
type DeviceReport struct {
	Engines []DeviceEngine `json:"engines"`
	Events  []DeviceEvent  `json:"events"`
}

// DeviceEngine is one grant's engine as it declared itself. Up is false
// while it restarts. A fact the engine has not declared is "" or 0.
type DeviceEngine struct {
	Grant    string `json:"grant"`
	Up       bool   `json:"up"`
	Class    string `json:"class"`
	Layout   string `json:"layout"`
	Version  string `json:"version"`
	GPU      string `json:"gpu"`
	CC       string `json:"cc"`
	Driver   string `json:"driver"`
	Capacity uint64 `json:"capacity"`
	Used     uint64 `json:"used"`
}

// DeviceEvent is one park that saved a device slice (Kind "park", MS the
// SAVE time) or one resume that restored one (Kind "restore", MS the
// RESTORE time). Seq rises from 1 per fiberd process. DeltaBytes is the
// delta's W bytes at a park and 0 at a restore. Session is "" when the
// fiber is anonymous.
type DeviceEvent struct {
	Seq        uint64  `json:"seq"`
	T          string  `json:"t"`
	Kind       string  `json:"kind"`
	Grant      string  `json:"grant"`
	Session    string  `json:"session"`
	Fence      string  `json:"fence"`
	DeltaBytes uint64  `json:"delta_bytes"`
	SliceBytes uint64  `json:"slice_bytes"`
	MS         float64 `json:"ms"`
}
