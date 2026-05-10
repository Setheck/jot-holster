// chrome.* API stubs injected into the popup before its scripts run, so
// popup.js can call chrome.storage / chrome.identity / chrome.runtime without
// a real extension host. The stubs use in-memory backing stores.
//
// Tests can pre-seed state by setting `window.__seed = { local, session }`
// BEFORE this script runs (Playwright's addInitScript ordering takes care of
// that — seed first, stubs second).

(() => {
  const seed = (typeof window !== "undefined" && window.__seed) || {};
  const localStore = { ...(seed.local || {}) };
  const sessionStore = { ...(seed.session || {}) };
  const listeners = [];

  function read(store, keys) {
    if (keys === null || keys === undefined) return { ...store };
    if (typeof keys === "string") return { [keys]: store[keys] };
    if (Array.isArray(keys)) {
      const out = {};
      for (const k of keys) out[k] = store[k];
      return out;
    }
    // object-form: keys with default values
    const out = {};
    for (const [k, dflt] of Object.entries(keys)) {
      out[k] = k in store ? store[k] : dflt;
    }
    return out;
  }

  function write(area, store, items) {
    const changes = {};
    for (const [k, v] of Object.entries(items)) {
      changes[k] = { oldValue: store[k], newValue: v };
      store[k] = v;
    }
    for (const fn of listeners) {
      try { fn(changes, area); } catch {}
    }
  }

  function drop(area, store, keys) {
    const list = Array.isArray(keys) ? keys : [keys];
    const changes = {};
    for (const k of list) {
      changes[k] = { oldValue: store[k], newValue: undefined };
      delete store[k];
    }
    for (const fn of listeners) {
      try { fn(changes, area); } catch {}
    }
  }

  const noop = () => {};
  const asyncNoop = () => Promise.resolve();

  window.chrome = {
    storage: {
      local: {
        get: (keys) => Promise.resolve(read(localStore, keys)),
        set: (items) => { write("local", localStore, items); return Promise.resolve(); },
        remove: (keys) => { drop("local", localStore, keys); return Promise.resolve(); },
      },
      session: {
        get: (keys) => Promise.resolve(read(sessionStore, keys)),
        set: (items) => { write("session", sessionStore, items); return Promise.resolve(); },
        remove: (keys) => { drop("session", sessionStore, keys); return Promise.resolve(); },
      },
      onChanged: { addListener: (fn) => listeners.push(fn) },
    },
    identity: {
      getRedirectURL: () => "https://test-extension.chromiumapp.org/",
      launchWebAuthFlow: () => Promise.reject(new Error("auth flow stubbed")),
    },
    runtime: {
      sendMessage: asyncNoop,
      onMessage: { addListener: noop },
      onInstalled: { addListener: noop },
      onStartup: { addListener: noop },
    },
    alarms: {
      create: asyncNoop,
      clear: asyncNoop,
      getAll: () => Promise.resolve([]),
      onAlarm: { addListener: noop },
    },
    declarativeNetRequest: {
      getDynamicRules: () => Promise.resolve([]),
      updateDynamicRules: asyncNoop,
    },
    action: {
      setBadgeText: asyncNoop,
      setBadgeBackgroundColor: asyncNoop,
    },
  };

  // expose stores for assertion / reset between tests
  window.__chromeStubs = { localStore, sessionStore, listeners };
})();
