package openprovider

import (
	"context"
	"sync"
)

// operationGate serializes zone mutations while still allowing callers to
// cancel while waiting for another provider operation to finish.
type operationGate struct {
	once sync.Once
	sem  chan struct{}
}

func (g *operationGate) acquire(ctx context.Context) error {
	g.once.Do(func() {
		g.sem = make(chan struct{}, 1)
		g.sem <- struct{}{}
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.sem:
		return nil
	}
}

func (g *operationGate) release() {
	g.sem <- struct{}{}
}
