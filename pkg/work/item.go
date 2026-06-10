package work

import "github.com/vigolium/vigolium/pkg/httpmsg"

// WorkItem represents a unit of work with lifecycle management.
// It wraps an HTTP request/response pair with an optional completion callback.
type WorkItem struct {
	Request       *httpmsg.HttpRequestResponse
	EnableModules []string // Per-task module selection (empty = use all)
	RecordUUID    string   // Pre-existing DB record UUID (skip store, use for findings)

	// StaticMeta marks a static-file request kept by the executor's
	// object-storage carve-out: it is fetched with HEAD and recorded as a
	// metadata-only http_record (body stripped) so the CDN traversal modules can
	// probe storage-fronted static assets without storing their (binary) bodies.
	StaticMeta bool

	onComplete func()
}

// NewWithModules creates a WorkItem with EnableModules but no callback.
// Use this for file/stdin/target sources when module filtering is needed.
func NewWithModules(request *httpmsg.HttpRequestResponse, enableModules []string) *WorkItem {
	return &WorkItem{
		Request:       request,
		EnableModules: enableModules,
	}
}

// NewWithCallback creates a WorkItem with completion callback.
// Use this for queue sources where tasks need to be acked after processing.
func NewWithCallback(request *httpmsg.HttpRequestResponse, enableModules []string, onComplete func()) *WorkItem {
	return &WorkItem{
		Request:       request,
		EnableModules: enableModules,
		onComplete:    onComplete,
	}
}

// Complete signals the work item has been processed.
// Safe to call even if onComplete is nil.
func (w *WorkItem) Complete() {
	if w.onComplete != nil {
		w.onComplete()
	}
}
