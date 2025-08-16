import { useEffect, useMemo, useRef, useState } from "react";

// ⚠️ Intentionally insecure demo app for local testing only.
// DO NOT deploy anywhere public.

const EXPOSED_PUBLIC_KEY = import.meta.env.VITE_PUBLIC_MAPS_KEY; // Sensitive info exposed on purpose

// naive deep merge (prototype pollution risk if input has __proto__/constructor)
function unsafeDeepMerge(target, source) {
  for (const key in source) {
    const val = source[key];
    if (val && typeof val === "object" && !Array.isArray(val)) {
      if (!target[key]) target[key] = {};
      unsafeDeepMerge(target[key], val);
    } else {
      target[key] = val;
    }
  }
  return target;
}

// pretend "DB" in client (IDOR possibilities)
const seedNotes = [
  { id: 1, owner: "alice", text: "Alice private note: salary=₹90k" },
  { id: 2, owner: "bob", text: "Bob private note: apiKey=abcd-1234" },
  { id: 3, owner: "admin", text: "Admin: rotate secrets quarterly." },
];

function useQuery() {
  const [params, setParams] = useState(() => new URLSearchParams(window.location.search));
  useEffect(() => {
    const onPop = () => setParams(new URLSearchParams(window.location.search));
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);
  return params;
}

function App() {
  const q = useQuery();
  const [user, setUser] = useState(() => {
    // weak “JWT” trust: any base64 JSON in localStorage is accepted
    const raw = localStorage.getItem("token");
    if (!raw) return { name: "guest", role: "user" };
    try {
      const parsed = JSON.parse(atob(raw));
      return parsed; // no signature check, fully trusted client-side
    } catch {
      return { name: "guest", role: "user" };
    }
  });

  const [notes, setNotes] = useState(() => {
    const s = localStorage.getItem("notes");
    return s ? JSON.parse(s) : seedNotes;
  });

  useEffect(() => {
    localStorage.setItem("notes", JSON.stringify(notes));
  }, [notes]);

  // 1) Reflected/DOM XSS vector via "msg" query + dangerouslySetInnerHTML
  const unsafeMsg = q.get("msg") || "<em>Hi!</em> Add ?msg=<b>Welcome</b>";

  // 2) Open redirect: /?next=https://example.com
  const next = q.get("next");

  // 3) ReDoS-prone regex: type something like (a+)+$ then test against a long string
  const [regexInput, setRegexInput] = useState("");
  const longHaystack = useMemo(() => "a".repeat(20000), []);

  // 4) Markdown preview with no sanitization -> XSS via HTML allowed
  const [mdInput, setMdInput] = useState("**Hello** _world_. <img src=x onerror=alert(1) />");

  // 5) Prototype pollution / config override via JSON
  const [configText, setConfigText] = useState(
    JSON.stringify(
      {
        theme: { rounded: true, compact: false },
        featureFlags: { newSearch: true },
      },
      null,
      2
    )
  );
  const appConfig = useRef({
    theme: { rounded: true, compact: false },
    featureFlags: { newSearch: false },
  });

  // 6) IDOR-ish edit: client-only “authorization”
  const [editingId, setEditingId] = useState(null);
  const [editText, setEditText] = useState("");

  // simulate login that sets arbitrary role/name into a base64 “token”
  const login = (name, role) => {
    const token = btoa(JSON.stringify({ name, role }));
    localStorage.setItem("token", token);
    setUser({ name, role });
  };

  const logout = () => {
    localStorage.removeItem("token");
    setUser({ name: "guest", role: "user" });
  };

  const handleRegexTest = () => {
    try {
      const r = new RegExp(regexInput); // no input limits, catastrophic backtracking possible
      const t0 = performance.now();
      const ok = r.test(longHaystack);
      const dt = Math.round(performance.now() - t0);
      alert(`Regex tested: ${ok} in ${dt}ms`);
    } catch (e) {
      alert("Invalid regex: " + e.message);
    }
  };

  const renderMarkdownUnsafe = (s) => {
    // super-naive markdown converter (no sanitization):
    // **bold** -> <b>, _i_ -> <i>, `code` -> <code>
    let html = s
      .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
      .replace(/_(.+?)_/g, "<i>$1</i>")
      .replace(/`(.+?)`/g, "<code>$1</code>");
    // allows raw HTML to pass through unchanged
    return { __html: html };
  };

  const startEdit = (n) => {
    setEditingId(n.id);
    setEditText(n.text);
  };

  const saveEdit = () => {
    if (editingId == null) return;

    // Client-side “auth” only:
    const n = notes.find((x) => x.id === editingId);
    const isOwner = n?.owner === user.name;
    const isAdmin = user.role === "admin"; // role fully client-controlled

    if (!isOwner && !isAdmin) {
      // looks like a check… but only on client :)
      alert("You are not allowed to edit this (client-side check)!");
      // still saves anyway (logic bug)
    }

    setNotes((prev) =>
      prev.map((x) => (x.id === editingId ? { ...x, text: editText } : x))
    );
    setEditingId(null);
    setEditText("");
  };

  const applyConfig = () => {
    try {
      const userCfg = JSON.parse(configText);
      unsafeDeepMerge(appConfig.current, userCfg); // can inject __proto__/constructor
      alert("Config applied.");
    } catch (e) {
      alert("Bad JSON: " + e.message);
    }
  };

  const doRedirect = () => {
    if (next) {
      // no allowlist, no origin checks
      window.location = next;
    } else {
      alert("Provide ?next=https://example.com to see redirect behavior");
    }
  };

  return (
    <div style={{ fontFamily: "ui-sans-serif, system-ui", padding: 24, lineHeight: 1.4 }}>
      <h1>Vuln Playground (React + Vite)</h1>
      <p style={{ opacity: 0.8, marginTop: -8 }}>
        For local testing only. Public key (intentionally leaked): <code>{EXPOSED_PUBLIC_KEY}</code>
      </p>

      {/* 1) Reflected / DOM XSS via query param */}
      <section style={card()}>
        <h2>Welcome Message (query param)</h2>
        <p>Try: <code>?msg=&lt;img src=x onerror=alert(1)&gt;</code></p>
        <div
          style={box()}
          dangerouslySetInnerHTML={{ __html: unsafeMsg }}
        />
      </section>

      {/* Login simulation with weak token trust */}
      <section style={card()}>
        <h2>Auth (client-trusted token)</h2>
        <p>Current user: <b>{user.name}</b> (role: <b>{user.role}</b>)</p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button onClick={() => login("alice", "user")}>Login as alice</button>
          <button onClick={() => login("bob", "user")}>Login as bob</button>
          <button onClick={() => login("admin", "admin")}>Login as admin</button>
          <button onClick={logout}>Logout</button>
          <button
            onClick={() => {
              const raw = prompt("Paste base64 token"); // any user can forge
              if (!raw) return;
              try {
                localStorage.setItem("token", raw);
                setUser(JSON.parse(atob(raw)));
              } catch (e) {
                alert("Bad token: " + e.message);
              }
            }}
          >
            Set Raw Token
          </button>
        </div>
      </section>

      {/* 6) IDOR-like edit with client-only checking */}
      <section style={card()}>
        <h2>Notes (IDOR-ish edit)</h2>
        <p>Anyone can attempt to edit any note; “auth” is only a client check.</p>
        <ul style={{ paddingLeft: 16 }}>
          {notes.map((n) => (
            <li key={n.id} style={{ marginBottom: 8 }}>
              <div><b>#{n.id}</b> owner=<code>{n.owner}</code></div>
              <div style={box()}>{n.text}</div>
              <div style={{ display: "flex", gap: 8 }}>
                <button onClick={() => startEdit(n)}>Edit</button>
              </div>
            </li>
          ))}
        </ul>
        {editingId != null && (
          <div style={{ marginTop: 8 }}>
            <textarea
              rows={3}
              style={{ width: "100%" }}
              value={editText}
              onChange={(e) => setEditText(e.target.value)}
            />
            <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
              <button onClick={saveEdit}>Save</button>
              <button onClick={() => setEditingId(null)}>Cancel</button>
            </div>
          </div>
        )}
      </section>

      {/* 3) Regex DoS */}
      <section style={card()}>
        <h2>Search (ReDoS-prone)</h2>
        <input
          placeholder="Enter regex e.g. (a+)+$"
          value={regexInput}
          onChange={(e) => setRegexInput(e.target.value)}
          style={{ width: "100%", marginBottom: 8 }}
        />
        <button onClick={handleRegexTest}>Test Regex on Long Text</button>
        <p style={{ opacity: 0.7 }}>This will run your regex on a 20k-char string.</p>
      </section>

      {/* 4) Unsanitized Markdown/HTML */}
      <section style={card()}>
        <h2>Markdown Preview (no sanitization)</h2>
        <textarea
          rows={5}
          style={{ width: "100%", marginBottom: 8 }}
          value={mdInput}
          onChange={(e) => setMdInput(e.target.value)}
        />
        <div
          style={box()}
          dangerouslySetInnerHTML={renderMarkdownUnsafe(mdInput)}
        />
      </section>

      {/* 2) Open Redirect */}
      <section style={card()}>
        <h2>Continue (open redirect)</h2>
        <p>Provide <code>?next=https://example.com</code> then click continue.</p>
        <button onClick={doRedirect}>Continue</button>
      </section>

      {/* 5) Prototype pollution-ish config override */}
      <section style={card()}>
        <h2>Config Override</h2>
        <p>Paste JSON to override app config (no safeguards). Try injecting special keys.</p>
        <textarea
          rows={6}
          style={{ width: "100%", marginBottom: 8 }}
          value={configText}
          onChange={(e) => setConfigText(e.target.value)}
        />
        <button onClick={applyConfig}>Apply Config</button>
        <pre style={{ marginTop: 8, background: "#f5f5f5", padding: 8 }}>
          {JSON.stringify(appConfig.current, null, 2)}
        </pre>
      </section>

      <footer style={{ marginTop: 24, opacity: 0.7 }}>
        <small>© demo for local security testing</small>
      </footer>
    </div>
  );
}

function card() {
  return {
    border: "1px solid #e5e7eb",
    borderRadius: 12,
    padding: 16,
    marginTop: 16,
    boxShadow: "0 1px 2px rgba(0,0,0,0.04)",
  };
}
function box() {
  return {
    border: "1px dashed #d1d5db",
    padding: 12,
    borderRadius: 8,
    background: "#fafafa",
  };
}

export default App;
