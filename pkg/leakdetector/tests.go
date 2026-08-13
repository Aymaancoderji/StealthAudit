package leakdetector

import (
	"context"
	"fmt"

	"github.com/stealthaudit/stealthaudit/pkg/orchestrator"
)

// setGetTest is the shared shape behind most of these checks: plant a
// unique marker in sessions[0], then look for it in sessions[1]. Finding
// it means the two sessions aren't actually isolated from each other.
type setGetTest struct {
	kind      LeakKind
	baseURL   string
	setScript func(marker string) string
	getScript string
	// interpret turns the raw Evaluate result from getScript into the
	// observed value (or "" if not observed/unsupported).
	interpret func(result any) (observed string, unsupported bool)
}

func (t *setGetTest) Kind() LeakKind { return t.kind }

func (t *setGetTest) Run(ctx context.Context, sessions []orchestrator.Session) (*Finding, error) {
	if len(sessions) != 2 {
		return nil, fmt.Errorf("%s leak test requires exactly 2 sessions, got %d", t.kind, len(sessions))
	}
	a, b := sessions[0], sessions[1]

	if err := a.Navigate(ctx, t.baseURL); err != nil {
		return nil, fmt.Errorf("navigating session A to test origin: %w", err)
	}
	if err := b.Navigate(ctx, t.baseURL); err != nil {
		return nil, fmt.Errorf("navigating session B to test origin: %w", err)
	}

	marker := randomMarker()

	var setResult any
	if err := a.Evaluate(ctx, t.setScript(marker), &setResult); err != nil {
		return nil, fmt.Errorf("planting marker in session A: %w", err)
	}
	if s, ok := setResult.(string); ok && s == "__unsupported__" {
		return &Finding{Kind: t.kind, Leaked: false, Detail: "not supported by this browser engine"}, nil
	}

	var raw any
	if err := b.Evaluate(ctx, t.getScript, &raw); err != nil {
		return nil, fmt.Errorf("reading marker from session B: %w", err)
	}

	observed, unsupported := t.interpret(raw)
	if unsupported {
		return &Finding{Kind: t.kind, Leaked: false, Detail: "not supported by this browser engine"}, nil
	}

	if observed == marker {
		return &Finding{
			Kind:   t.kind,
			Leaked: true,
			Detail: "marker planted in session A was readable from session B",
		}, nil
	}
	return &Finding{Kind: t.kind, Leaked: false}, nil
}

func stringInterpret(raw any) (string, bool) {
	s, _ := raw.(string)
	return s, false
}

// NewCookieTest checks whether a cookie set in one session is readable
// from another session against the same origin.
func NewCookieTest(baseURL string) LeakTest {
	return &setGetTest{
		kind:    LeakCookie,
		baseURL: baseURL,
		setScript: func(marker string) string {
			return fmt.Sprintf(`(() => { document.cookie = 'stealthaudit_marker=%s; path=/'; return true; })()`, marker)
		},
		getScript: `(() => { const m = document.cookie.match(/stealthaudit_marker=([^;]+)/); return m ? m[1] : ''; })()`,
		interpret: stringInterpret,
	}
}

// NewLocalStorageTest checks whether a localStorage entry set in one
// session is readable from another session against the same origin.
func NewLocalStorageTest(baseURL string) LeakTest {
	return &setGetTest{
		kind:    LeakLocalStorage,
		baseURL: baseURL,
		setScript: func(marker string) string {
			return fmt.Sprintf(`(() => { localStorage.setItem('stealthaudit_marker', '%s'); return true; })()`, marker)
		},
		getScript: `(() => { return localStorage.getItem('stealthaudit_marker') || ''; })()`,
		interpret: stringInterpret,
	}
}

// NewIndexedDBTest checks whether an IndexedDB record written in one
// session is readable from another session against the same origin.
func NewIndexedDBTest(baseURL string) LeakTest {
	return &setGetTest{
		kind:    LeakIndexedDB,
		baseURL: baseURL,
		setScript: func(marker string) string {
			return fmt.Sprintf(`(async () => {
  return await new Promise((resolve, reject) => {
    const req = indexedDB.open('stealthaudit_db', 1);
    req.onupgradeneeded = () => { req.result.createObjectStore('kv'); };
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction('kv', 'readwrite');
      tx.objectStore('kv').put('%s', 'marker');
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => reject(tx.error);
    };
    req.onerror = () => reject(req.error);
  });
})()`, marker)
		},
		getScript: `(async () => {
  return await new Promise((resolve, reject) => {
    const req = indexedDB.open('stealthaudit_db', 1);
    req.onupgradeneeded = () => { req.result.createObjectStore('kv'); };
    req.onsuccess = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('kv')) { resolve(''); return; }
      const tx = db.transaction('kv', 'readonly');
      const getReq = tx.objectStore('kv').get('marker');
      getReq.onsuccess = () => resolve(getReq.result || '');
      getReq.onerror = () => reject(getReq.error);
    };
    req.onerror = () => reject(req.error);
  });
})()`,
		interpret: stringInterpret,
	}
}

// NewSharedWorkerTest checks whether two sessions connecting to a
// same-named SharedWorker land on the same worker instance (and can thus
// pass state to each other), which shouldn't happen across isolated
// profiles/contexts.
func NewSharedWorkerTest(baseURL string) LeakTest {
	return &setGetTest{
		kind:    LeakSharedWorker,
		baseURL: baseURL,
		setScript: func(marker string) string {
			return fmt.Sprintf(`(async () => {
  if (typeof SharedWorker === 'undefined') return '__unsupported__';
  return await new Promise((resolve, reject) => {
    try {
      const w = new SharedWorker('/shared-worker.js', 'stealthaudit-worker');
      w.port.onmessage = () => resolve(true);
      w.port.onmessageerror = reject;
      w.port.postMessage({ type: 'set', value: '%s' });
      w.port.start();
    } catch (e) { resolve('__unsupported__'); }
  });
})()`, marker)
		},
		getScript: `(async () => {
  if (typeof SharedWorker === 'undefined') return '__unsupported__';
  return await new Promise((resolve, reject) => {
    try {
      const w = new SharedWorker('/shared-worker.js', 'stealthaudit-worker');
      w.port.onmessage = (e) => resolve((e.data && e.data.value) || '');
      w.port.onmessageerror = reject;
      w.port.postMessage({ type: 'get' });
      w.port.start();
    } catch (e) { resolve('__unsupported__'); }
  });
})()`,
		interpret: func(raw any) (string, bool) {
			s, _ := raw.(string)
			return s, s == "__unsupported__"
		},
	}
}

// NewServiceWorkerTest checks whether a service worker registered/primed
// by one session ends up controlling and answering fetches from another,
// supposedly isolated, session.
func NewServiceWorkerTest(baseURL string) LeakTest {
	return &setGetTest{
		kind:    LeakServiceWorker,
		baseURL: baseURL,
		setScript: func(marker string) string {
			return fmt.Sprintf(`(async () => {
  if (!('serviceWorker' in navigator)) return '__unsupported__';
  try {
    const reg = await navigator.serviceWorker.register('/service-worker.js', { scope: '/' });
    await new Promise((resolve) => {
      if (reg.active) return resolve();
      const worker = reg.installing || reg.waiting;
      if (!worker) return resolve();
      worker.addEventListener('statechange', () => {
        if (worker.state === 'activated') resolve();
      });
    });
    const ctrl = navigator.serviceWorker.controller || reg.active;
    if (!ctrl) return '__unsupported__';
    return await new Promise((resolve) => {
      const channel = new MessageChannel();
      channel.port1.onmessage = () => resolve(true);
      ctrl.postMessage({ type: 'set', value: '%s' }, [channel.port2]);
      setTimeout(() => resolve('__unsupported__'), 3000);
    });
  } catch (e) { return '__unsupported__'; }
})()`, marker)
		},
		getScript: `(async () => {
  try {
    const res = await fetch('/sw-marker');
    return await res.text();
  } catch (e) { return '__unsupported__'; }
})()`,
		interpret: func(raw any) (string, bool) {
			s, _ := raw.(string)
			return s, s == "__unsupported__"
		},
	}
}

// AllTests returns the standard suite of leak tests against a leak
// detector Server started at baseURL.
func AllTests(baseURL string) []LeakTest {
	return []LeakTest{
		NewCookieTest(baseURL),
		NewLocalStorageTest(baseURL),
		NewIndexedDBTest(baseURL),
		NewSharedWorkerTest(baseURL),
		NewServiceWorkerTest(baseURL),
	}
}
