import Crypto
import Foundation

enum NoctwebPublisherSurfaceError: Error, Equatable {
    case invalidHostSigningPublicKey
    case invalidOperatorSuffix
}

struct NoctwebPublisherResponse: Equatable {
    let statusCode: Int
    let contentType: String
    let body: Data
    let headers: [String: String]
}

struct NoctwebPublisherSurface {
    let relayNamespaceID: String
    let relaySuffix: String
    let usesCustomSuffix: Bool

    private let hostSigningPublicKey: Data
    private let configBody: Data

    init(hostSigningPublicKey: Data, operatorSuffix: String?) throws {
        guard hostSigningPublicKey.count == 32 else {
            throw NoctwebPublisherSurfaceError.invalidHostSigningPublicKey
        }
        self.hostSigningPublicKey = hostSigningPublicKey

        var namespaceMaterial = Data(
            "org.noctweave.noctweb/relay-namespace-id/v1".utf8
        )
        namespaceMaterial.append(0)
        namespaceMaterial.append(hostSigningPublicKey)
        let digest = Data(SHA256.hash(data: namespaceMaterial))
        relayNamespaceID = "sha256:\(Self.hex(digest))"

        if let operatorSuffix {
            relaySuffix = try Self.canonicalOperatorSuffix(operatorSuffix)
            usesCustomSuffix = true
        } else {
            relaySuffix = "r-\(Self.base32(Data(digest.prefix(10))))"
            usesCustomSuffix = false
        }

        let config = Config(
            version: 1,
            relayNamespaceID: relayNamespaceID,
            relaySuffix: relaySuffix,
            usesCustomSuffix: usesCustomSuffix,
            hostSigningPublicKey: hostSigningPublicKey.base64EncodedString(),
            hostModule: "nw.net-host",
            hostModuleVersion: 1,
            maximumObjectBytes: NoctweaveNetLimits.maximumHostObjectBytes,
            minimumRetentionSeconds: NoctweaveNetLimits.minimumHostRetentionSeconds,
            maximumRetentionSeconds: NoctweaveNetLimits.maximumHostRetentionSeconds
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        configBody = try encoder.encode(config)
    }

    func response(method: String, uri: String) -> NoctwebPublisherResponse? {
        let path = uri.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
            .first
            .map(String.init) ?? uri
        guard path == "/noctweb" || path.hasPrefix("/noctweb/") else {
            return nil
        }

        let knownPath = path == "/noctweb"
            || path == "/noctweb/"
            || path == "/noctweb/assets/app.css"
            || path == "/noctweb/assets/app.js"
            || path == "/noctweb/config.json"
        guard knownPath else {
            return Self.makeResponse(
                statusCode: 404,
                contentType: "application/json; charset=utf-8",
                body: Data(#"{"error":"Not found"}"#.utf8),
                headers: Self.apiHeaders
            )
        }
        guard method == "GET" || method == "HEAD" else {
            return Self.makeResponse(
                statusCode: 405,
                contentType: "application/json; charset=utf-8",
                body: Data(#"{"error":"Method not allowed"}"#.utf8),
                headers: Self.apiHeaders.merging(["Allow": "GET, HEAD"]) { _, new in new }
            )
        }
        if path == "/noctweb" {
            return Self.makeResponse(
                statusCode: 308,
                contentType: "text/plain; charset=utf-8",
                body: Data(),
                headers: Self.documentHeaders.merging(["Location": "/noctweb/"]) { _, new in new }
            )
        }
        switch path {
        case "/noctweb/":
            return Self.makeResponse(
                statusCode: 200,
                contentType: "text/html; charset=utf-8",
                body: Data(Self.html.utf8),
                headers: Self.documentHeaders
            )
        case "/noctweb/assets/app.css":
            return Self.makeResponse(
                statusCode: 200,
                contentType: "text/css; charset=utf-8",
                body: Data(Self.css.utf8),
                headers: Self.assetHeaders
            )
        case "/noctweb/assets/app.js":
            return Self.makeResponse(
                statusCode: 200,
                contentType: "text/javascript; charset=utf-8",
                body: Data(Self.javascript.utf8),
                headers: Self.assetHeaders
            )
        case "/noctweb/config.json":
            return Self.makeResponse(
                statusCode: 200,
                contentType: "application/json; charset=utf-8",
                body: configBody,
                headers: Self.apiHeaders
            )
        default:
            return nil
        }
    }

    static func canonicalOperatorSuffix(_ value: String) throws -> String {
        let candidate = value.hasPrefix(".") ? String(value.dropFirst()) : value
        guard !candidate.hasPrefix("r-"),
              !candidate.hasPrefix("xn--"),
              (1...32).contains(candidate.utf8.count),
              candidate == candidate.lowercased(),
              candidate.unicodeScalars.allSatisfy({ scalar in
                  scalar.isASCII
                      && ((97...122).contains(scalar.value)
                          || (48...57).contains(scalar.value)
                          || scalar.value == 45)
              }),
              candidate.first?.isLetter == true || candidate.first?.isNumber == true,
              candidate.last?.isLetter == true || candidate.last?.isNumber == true
        else {
            throw NoctwebPublisherSurfaceError.invalidOperatorSuffix
        }
        return candidate
    }

    private static func makeResponse(
        statusCode: Int,
        contentType: String,
        body: Data,
        headers: [String: String]
    ) -> NoctwebPublisherResponse {
        NoctwebPublisherResponse(
            statusCode: statusCode,
            contentType: contentType,
            body: body,
            headers: headers
        )
    }

    private struct Config: Codable {
        let version: Int
        let relayNamespaceID: String
        let relaySuffix: String
        let usesCustomSuffix: Bool
        let hostSigningPublicKey: String
        let hostModule: String
        let hostModuleVersion: Int
        let maximumObjectBytes: Int
        let minimumRetentionSeconds: Int
        let maximumRetentionSeconds: Int
    }

    private static let publisherCSP = [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data: blob:",
        "connect-src 'self'",
        "frame-src blob:",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "worker-src 'none'",
        "manifest-src 'none'"
    ].joined(separator: "; ")

    private static let documentHeaders: [String: String] = [
        "Cache-Control": "no-store",
        "Content-Security-Policy": publisherCSP,
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY"
    ]

    private static let assetHeaders = documentHeaders.merging([
        "Cache-Control": "no-store"
    ]) { _, new in new }

    private static let apiHeaders = documentHeaders.merging([
        "Cache-Control": "no-store"
    ]) { _, new in new }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func base32(_ data: Data) -> String {
        let alphabet = Array("abcdefghijklmnopqrstuvwxyz234567")
        var accumulator = 0
        var bitCount = 0
        var output = ""
        for byte in data {
            accumulator = (accumulator << 8) | Int(byte)
            bitCount += 8
            while bitCount >= 5 {
                bitCount -= 5
                output.append(alphabet[(accumulator >> bitCount) & 0x1f])
            }
            accumulator = bitCount == 0
                ? 0
                : accumulator & ((1 << bitCount) - 1)
        }
        if bitCount > 0 {
            output.append(alphabet[(accumulator << (5 - bitCount)) & 0x1f])
        }
        return output
    }

    private static let html = #"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Noctweb Publisher</title>
      <link rel="stylesheet" href="/noctweb/assets/app.css">
      <script src="/noctweb/assets/app.js" defer></script>
    </head>
    <body>
      <div class="app-shell">
        <header class="topbar">
          <a class="brand" href="/noctweb/" aria-label="Noctweb Publisher home">
            <span class="brand-mark" aria-hidden="true">N</span>
            <span><strong>Noctweb</strong><small>Publisher</small></span>
          </a>
          <div class="topbar-context">
            <span class="connection-dot" aria-hidden="true"></span>
            <span id="relayLabel">Connecting to relay…</span>
          </div>
          <div class="topbar-actions">
            <label class="appearance-control" for="appearanceSelect"><span>Appearance</span><select id="appearanceSelect" aria-label="Appearance"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></label>
            <button class="button ghost" id="resetButton" type="button">Reset draft</button>
            <button class="button primary" id="hostButton" type="button">Host revision</button>
          </div>
        </header>

        <main class="product">
          <section class="project-heading" aria-labelledby="projectTitle">
            <div>
              <p class="eyebrow">Publication workspace</p>
              <h1 id="projectTitle">Build a page that belongs to its publisher.</h1>
              <p class="muted">Design visually or edit browser-ready HTML, CSS, and JavaScript. The relay stores signed bytes; it never owns or executes the site.</p>
            </div>
            <div class="identity-chip" id="identityChip">
              <span>Publisher identity</span>
              <strong id="publisherShort">Preparing…</strong>
            </div>
          </section>

          <nav class="workspace-tabs" aria-label="Publisher workspace">
            <button class="tab active" data-tab="design" type="button">Design</button>
            <button class="tab" data-tab="code" type="button">Code</button>
            <button class="tab" data-tab="preview" type="button">Preview</button>
          </nav>

          <section class="workspace">
            <div class="panel active" data-panel="design">
              <div class="form-layout">
                <section class="form-card">
                  <div class="section-heading">
                    <div><p class="eyebrow">Page</p><h2>Content</h2></div>
                    <span class="save-state" id="saveState">Saved locally</span>
                  </div>
                  <label>Site label
                    <span class="address-field">
                      <input id="siteLabel" maxlength="48" autocomplete="off" spellcheck="false">
                      <span id="suffixText">.relay</span>
                    </span>
                  </label>
                  <label>Title<input id="titleInput" maxlength="120"></label>
                  <label>Subtitle<input id="subtitleInput" maxlength="180"></label>
                  <label>Body<textarea id="bodyInput" rows="7" maxlength="4000"></textarea></label>
                </section>
                <section class="form-card">
                  <div class="section-heading"><div><p class="eyebrow">Style</p><h2>Appearance</h2></div></div>
                  <label>Accent color
                    <span class="color-field">
                      <input id="accentInput" type="color">
                      <output id="accentValue">#7c6cff</output>
                    </span>
                  </label>
                  <label>Button label<input id="buttonTextInput" maxlength="64"></label>
                  <label>Button destination<input id="buttonURLInput" maxlength="400" placeholder="https://example.com"></label>
                  <div class="notice" id="customCodeNotice" hidden>
                    <strong>Custom code is active.</strong>
                    <p>Design changes will not overwrite it. Apply the design template when you want to replace the source files.</p>
                    <button class="button secondary" id="applyDesignButton" type="button">Apply design to code</button>
                  </div>
                </section>
              </div>
            </div>

            <div class="panel" data-panel="code">
              <div class="code-toolbar">
                <div class="file-tabs" role="tablist" aria-label="Source file">
                  <button class="file-tab active" data-file="html" type="button">index.html</button>
                  <button class="file-tab" data-file="css" type="button">styles.css</button>
                  <button class="file-tab" data-file="js" type="button">app.js</button>
                </div>
                <span>HTML · CSS · JS · compiled React compatible</span>
              </div>
              <textarea class="code-editor" id="codeEditor" aria-label="Source editor" spellcheck="false"></textarea>
            </div>

            <div class="panel preview-panel" data-panel="preview">
              <div class="preview-toolbar">
                <div>
                  <strong id="previewAddress">noct://site.relay/</strong>
                  <span id="verificationState">Local draft · sandboxed</span>
                </div>
                <button class="button secondary" id="refreshPreviewButton" type="button">Refresh preview</button>
              </div>
              <iframe id="previewFrame" title="Sandboxed Noctweb page preview" sandbox="allow-scripts"></iframe>
            </div>
          </section>

          <section class="publication-card" aria-labelledby="hostedHeading">
            <div>
              <p class="eyebrow">Current relay copy</p>
              <h2 id="hostedHeading">Not hosted yet</h2>
              <p id="hostedDetail" class="muted">Host a signed revision when it is ready to test through this relay.</p>
            </div>
            <div class="publication-actions">
              <button class="button secondary" id="copyLinkButton" type="button" disabled>Copy test link</button>
              <button class="button danger" id="unhostButton" type="button" disabled>Unhost copy</button>
            </div>
          </section>
        </main>
      </div>

      <dialog id="hostDialog">
        <form method="dialog" id="hostForm">
          <div class="dialog-heading">
            <div><p class="eyebrow">Host capability</p><h2 id="dialogTitle">Host this revision</h2></div>
            <button class="icon-button" value="cancel" aria-label="Close" type="submit">×</button>
          </div>
          <p id="dialogDescription" class="muted">The publisher key stays in this browser. The password authorizes only this relay write and is not saved.</p>
          <label>Publisher password
            <input id="passwordInput" type="password" minlength="12" maxlength="4096" autocomplete="off" required>
          </label>
          <label id="retentionField">Retention
            <select id="retentionInput">
              <option value="86400">1 day</option>
              <option value="604800" selected>7 days</option>
              <option value="2592000">30 days</option>
            </select>
          </label>
          <div class="dialog-note">
            <strong>Hosted is not finalized.</strong>
            <span>A hosting receipt proves bounded storage at this relay. Consensus naming and publisher-head finality come later.</span>
          </div>
          <p class="form-error" id="dialogError" role="alert"></p>
          <div class="dialog-actions">
            <button class="button ghost" value="cancel" type="submit">Cancel</button>
            <button class="button primary" id="dialogSubmit" value="default" type="submit">Host revision</button>
          </div>
        </form>
      </dialog>

      <div class="toast" id="toast" role="status" aria-live="polite"></div>
    </body>
    </html>
    """#

    private static let css = #"""
    :root {
      color-scheme: light dark;
      --bg: #090b10;
      --surface: #11141c;
      --surface-2: #171b25;
      --line: #272c39;
      --text: #f4f5f8;
      --muted: #989faf;
      --accent: #7c6cff;
      --accent-strong: #9588ff;
      --success: #44d49b;
      --danger: #ff7185;
      --radius: 14px;
      --shadow: 0 22px 70px rgba(0, 0, 0, .28);
      font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; min-height: 100%; background: var(--bg); }
    body {
      min-width: 320px;
      background:
        radial-gradient(circle at 15% -10%, rgba(124, 108, 255, .18), transparent 34rem),
        var(--bg);
    }
    button, input, textarea, select { font: inherit; }
    button { color: inherit; }
    .app-shell { min-height: 100vh; }
    .topbar {
      position: sticky;
      top: 0;
      z-index: 10;
      min-height: 68px;
      display: grid;
      grid-template-columns: 1fr auto 1fr;
      align-items: center;
      gap: 24px;
      padding: 10px clamp(18px, 3vw, 44px);
      border-bottom: 1px solid rgba(255,255,255,.07);
      background: rgba(9, 11, 16, .88);
      backdrop-filter: blur(18px);
    }
    .brand {
      width: max-content;
      display: inline-flex;
      align-items: center;
      gap: 11px;
      color: var(--text);
      text-decoration: none;
    }
    .brand-mark {
      display: grid;
      place-items: center;
      width: 38px;
      height: 38px;
      border: 1px solid rgba(255,255,255,.18);
      border-radius: 11px;
      background: linear-gradient(145deg, #a69cff, #5b49ed);
      box-shadow: 0 8px 24px rgba(92, 72, 237, .35);
      font-weight: 850;
    }
    .brand strong, .brand small { display: block; line-height: 1.05; }
    .brand strong { font-size: 15px; letter-spacing: .01em; }
    .brand small { margin-top: 4px; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .12em; }
    .topbar-context {
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
    }
    .connection-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--success); box-shadow: 0 0 0 4px rgba(68,212,155,.1); }
    .topbar-actions { display: flex; justify-content: flex-end; gap: 9px; }
    .product {
      width: min(1180px, calc(100% - 36px));
      margin: 0 auto;
      padding: clamp(30px, 5vw, 64px) 0 60px;
    }
    .project-heading {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      gap: 36px;
      margin-bottom: 28px;
    }
    .project-heading h1 { max-width: 720px; margin: 7px 0 10px; font-size: clamp(28px, 4vw, 46px); line-height: 1.06; letter-spacing: -.035em; }
    .project-heading .muted { max-width: 700px; margin: 0; }
    .eyebrow { margin: 0; color: var(--accent-strong); font-size: 11px; font-weight: 750; letter-spacing: .13em; text-transform: uppercase; }
    .muted { color: var(--muted); line-height: 1.55; }
    .identity-chip {
      min-width: 205px;
      padding: 13px 15px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: rgba(17,20,28,.75);
    }
    .identity-chip span, .identity-chip strong { display: block; }
    .identity-chip span { margin-bottom: 5px; color: var(--muted); font-size: 11px; }
    .identity-chip strong { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .workspace-tabs { display: flex; gap: 4px; width: max-content; padding: 4px; margin-bottom: 12px; border: 1px solid var(--line); border-radius: 12px; background: #0d1016; }
    .tab, .file-tab {
      border: 0;
      background: transparent;
      color: var(--muted);
      cursor: pointer;
      transition: .16s ease;
    }
    .tab { min-width: 92px; padding: 9px 16px; border-radius: 8px; font-size: 13px; font-weight: 650; }
    .tab:hover, .file-tab:hover { color: var(--text); }
    .tab.active { color: var(--text); background: var(--surface-2); box-shadow: inset 0 0 0 1px rgba(255,255,255,.05); }
    .workspace {
      min-height: min(650px, calc(100vh - 250px));
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: rgba(17, 20, 28, .94);
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .panel { display: none; min-height: inherit; }
    .panel.active { display: block; }
    .form-layout { display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(280px, .75fr); gap: 1px; min-height: inherit; background: var(--line); }
    .form-card { padding: clamp(24px, 4vw, 42px); background: var(--surface); }
    .section-heading { display: flex; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 28px; }
    .section-heading h2, .publication-card h2, .dialog-heading h2 { margin: 5px 0 0; font-size: 20px; letter-spacing: -.02em; }
    .save-state { color: var(--success); font-size: 11px; }
    label { display: grid; gap: 8px; margin: 0 0 20px; color: #c6cad4; font-size: 12px; font-weight: 650; }
    input, textarea, select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 9px;
      outline: none;
      background: #0c0f15;
      color: var(--text);
      padding: 11px 12px;
      transition: border .15s, box-shadow .15s;
    }
    textarea { resize: vertical; line-height: 1.55; }
    input:focus, textarea:focus, select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(124,108,255,.13); }
    .address-field { display: grid; grid-template-columns: 1fr auto; align-items: center; }
    .address-field input { border-radius: 9px 0 0 9px; }
    .address-field span { height: 100%; display: flex; align-items: center; padding: 0 12px; border: 1px solid var(--line); border-left: 0; border-radius: 0 9px 9px 0; background: var(--surface-2); color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; }
    .color-field { display: grid; grid-template-columns: 48px 1fr; gap: 9px; }
    .color-field input { height: 42px; padding: 5px; }
    .color-field output { display: flex; align-items: center; padding: 0 12px; border: 1px solid var(--line); border-radius: 9px; background: #0c0f15; color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .notice, .dialog-note { padding: 14px; border: 1px solid rgba(124,108,255,.25); border-radius: 10px; background: rgba(124,108,255,.07); }
    .notice p { margin: 7px 0 13px; color: var(--muted); font-size: 12px; line-height: 1.5; }
    .code-toolbar, .preview-toolbar {
      min-height: 55px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      padding: 8px 14px;
      border-bottom: 1px solid var(--line);
      background: #0d1016;
    }
    .code-toolbar > span { color: var(--muted); font-size: 11px; }
    .file-tabs { display: flex; gap: 3px; }
    .file-tab { padding: 8px 12px; border-radius: 7px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; }
    .file-tab.active { color: var(--text); background: var(--surface-2); }
    .code-editor {
      display: block;
      width: 100%;
      height: calc(min(650px, 100vh - 250px) - 55px);
      min-height: 520px;
      padding: 24px;
      border: 0;
      border-radius: 0;
      resize: none;
      background: #090b10;
      color: #d8dbea;
      font: 13px/1.65 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      tab-size: 2;
    }
    .preview-panel.active { display: flex; flex-direction: column; }
    .preview-toolbar > div { display: grid; gap: 4px; min-width: 0; }
    .preview-toolbar strong { overflow: hidden; text-overflow: ellipsis; font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; }
    .preview-toolbar span { color: var(--muted); font-size: 11px; }
    #previewFrame { width: 100%; flex: 1; min-height: 580px; border: 0; background: #fff; }
    .publication-card {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 30px;
      margin-top: 16px;
      padding: 20px 22px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: rgba(17,20,28,.82);
    }
    .publication-card p { margin: 7px 0 0; }
    .publication-actions { display: flex; gap: 8px; flex-shrink: 0; }
    .button, .icon-button {
      border: 1px solid transparent;
      border-radius: 9px;
      cursor: pointer;
      font-size: 12px;
      font-weight: 700;
      transition: transform .12s, background .15s, border .15s;
    }
    .button { min-height: 38px; padding: 0 15px; }
    .button:hover:not(:disabled) { transform: translateY(-1px); }
    .button:disabled { opacity: .42; cursor: not-allowed; }
    .button.primary { background: var(--accent); color: white; box-shadow: 0 9px 24px rgba(124,108,255,.22); }
    .button.primary:hover { background: var(--accent-strong); }
    .button.secondary { border-color: var(--line); background: var(--surface-2); }
    .button.ghost { border-color: var(--line); background: transparent; color: #c6cad4; }
    .button.danger { border-color: rgba(255,113,133,.3); background: rgba(255,113,133,.08); color: #ff9aa8; }
    dialog {
      width: min(500px, calc(100% - 28px));
      padding: 0;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: var(--surface);
      color: var(--text);
      box-shadow: 0 35px 100px rgba(0,0,0,.58);
    }
    dialog::backdrop { background: rgba(2,4,8,.7); backdrop-filter: blur(8px); }
    dialog form { padding: 26px; }
    .dialog-heading { display: flex; justify-content: space-between; gap: 20px; margin-bottom: 12px; }
    .icon-button { width: 34px; height: 34px; border-color: var(--line); background: transparent; font-size: 20px; font-weight: 400; }
    .dialog-note { display: grid; gap: 5px; margin: 6px 0 16px; }
    .dialog-note span { color: var(--muted); font-size: 11px; line-height: 1.5; }
    .dialog-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
    .form-error { min-height: 18px; margin: 0; color: var(--danger); font-size: 12px; }
    .toast {
      position: fixed;
      right: 22px;
      bottom: 22px;
      z-index: 30;
      max-width: min(390px, calc(100% - 44px));
      padding: 12px 15px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #171b25;
      box-shadow: var(--shadow);
      color: var(--text);
      font-size: 12px;
      opacity: 0;
      transform: translateY(10px);
      pointer-events: none;
      transition: .2s ease;
    }
    .toast.visible { opacity: 1; transform: translateY(0); }
    @media (max-width: 820px) {
      .topbar { grid-template-columns: 1fr auto; }
      .topbar-context { display: none; }
      .project-heading, .publication-card { align-items: flex-start; flex-direction: column; }
      .identity-chip { width: 100%; }
      .form-layout { grid-template-columns: 1fr; }
      .publication-actions { width: 100%; }
      .publication-actions .button { flex: 1; }
    }
    @media (max-width: 560px) {
      .topbar { padding: 9px 14px; }
      .topbar-actions .ghost { display: none; }
      .product { width: min(100% - 20px, 1180px); padding-top: 28px; }
      .workspace-tabs { width: 100%; }
      .tab { flex: 1; min-width: 0; }
      .form-card { padding: 22px 17px; }
      .code-toolbar > span { display: none; }
      .code-editor { min-height: 500px; padding: 18px 14px; font-size: 12px; }
      .preview-toolbar { align-items: flex-start; }
      .publication-actions { flex-direction: column; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { scroll-behavior: auto !important; transition: none !important; }
    }
    :root { color-scheme: light; --shell-bg: #fffaf5; --shell-surface: #fffdf9; --shell-surface-raised: #f6eee8; --shell-border: #e6d8d0; --shell-text: #321a23; --shell-muted: #765f67; --shell-accent: #c96a61; --shell-accent-strong: #922d35; --shell-focus: #922d35; --bg: var(--shell-bg); --surface: var(--shell-surface); --surface-2: var(--shell-surface-raised); --line: var(--shell-border); --text: var(--shell-text); --muted: var(--shell-muted); --accent: var(--shell-accent); --accent-strong: var(--shell-accent-strong); }
    :root[data-theme="dark"] { color-scheme: dark; --shell-bg: #1b1217; --shell-surface: #2a1b21; --shell-surface-raised: #38252b; --shell-border: #5a3c43; --shell-text: #faf3ea; --shell-muted: #c8adb0; --shell-accent: #c96a61; --shell-accent-strong: #ebc7af; --shell-focus: #ebc7af; --bg: var(--shell-bg); --surface: var(--shell-surface); --surface-2: var(--shell-surface-raised); --line: var(--shell-border); --text: var(--shell-text); --muted: var(--shell-muted); --accent: var(--shell-accent); --accent-strong: var(--shell-accent-strong); }
    :root[data-theme="system"] { color-scheme: light dark; }
    @media (prefers-color-scheme: dark) { :root[data-theme="system"] { --shell-bg: #1b1217; --shell-surface: #2a1b21; --shell-surface-raised: #38252b; --shell-border: #5a3c43; --shell-text: #faf3ea; --shell-muted: #c8adb0; --shell-accent: #c96a61; --shell-accent-strong: #ebc7af; --shell-focus: #ebc7af; --bg: var(--shell-bg); --surface: var(--shell-surface); --surface-2: var(--shell-surface-raised); --line: var(--shell-border); --text: var(--shell-text); --muted: var(--shell-muted); --accent: var(--shell-accent); --accent-strong: var(--shell-accent-strong); } }
    body { background: var(--shell-bg); padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left); }
    .topbar { border-bottom-color: var(--shell-border); background: color-mix(in srgb, var(--shell-surface) 90%, transparent); }
    .form-card, .workspace, .publication-card, dialog { background: color-mix(in srgb, var(--shell-surface) 94%, transparent); }
    input, textarea, select { background: var(--shell-surface-raised); color: var(--shell-text); }
    button:focus-visible, input:focus-visible, textarea:focus-visible, select:focus-visible { outline: 2px solid var(--shell-focus); outline-offset: 2px; }
    .appearance-control { display: inline-flex; align-items: center; gap: 7px; margin: 0; color: var(--shell-muted); font-size: 11px; font-weight: 650; white-space: nowrap; }
    .appearance-control span { display: none; }
    .appearance-control select { width: auto; min-height: 38px; padding: 0 28px 0 10px; border-radius: 9px; }
    .brand-mark { background: linear-gradient(145deg, #c96a61, #922d35); box-shadow: 0 8px 24px rgba(146,45,53,.28); }
    .button.primary { background: var(--shell-accent); box-shadow: 0 9px 24px rgba(146,45,53,.22); }
    .button.primary:hover { background: var(--shell-accent-strong); }
    .button.ghost { color: var(--shell-muted); }
    @media (max-width: 560px) { .appearance-control span { display: inline; } .topbar { padding-top: calc(9px + env(safe-area-inset-top)); } .product { padding-bottom: calc(60px + env(safe-area-inset-bottom)); } }
    """#

    private static let javascript = #"""
    "use strict";
    (() => {
      const CAPSULE_PROFILE = "noctweb-hosted-capsule-v1";
      const PROTOCOL_VERSION = "noctweb-lab-v3";
      const SIGNED_HEAD_DOMAIN = "org.noctweave.noctweb/signed-head/v3";
      const HEAD_HASH_DOMAIN = "org.noctweave.noctweb/head-hash/v1";
      const PUBLISHER_ID_DOMAIN = "org.noctweave.noctweb/publisher-id/v1";
      const RELEASE_DOMAIN = "org.noctweave.net/host-release/v1";
      const DB_NAME = "noctweb-publisher-v1";
      const DB_VERSION = 1;
      const PROJECT_KEY = "current";
      const MAX_TRACKED_HOSTED_COPIES = 64;
      const encoder = new TextEncoder();
      const decoder = new TextDecoder("utf-8", { fatal: true });
      const elements = Object.fromEntries([
        "relayLabel", "publisherShort", "identityChip", "siteLabel", "suffixText",
        "titleInput", "subtitleInput", "bodyInput", "accentInput", "accentValue",
        "buttonTextInput", "buttonURLInput", "customCodeNotice", "applyDesignButton",
        "saveState", "codeEditor", "previewAddress", "verificationState", "previewFrame",
        "refreshPreviewButton", "resetButton", "hostButton", "hostedHeading",
        "hostedDetail", "copyLinkButton", "unhostButton", "hostDialog", "hostForm",
        "dialogTitle", "dialogDescription", "passwordInput", "retentionField",
        "retentionInput", "dialogError", "dialogSubmit", "toast", "appearanceSelect"
      ].map((id) => [id, document.getElementById(id)]));

      let config;
      let database;
      let project;
      let identity;
      let currentFile = "html";
      let hostedCopies = [];
      let currentHosted = null;
      let currentHostedVerified = false;
      let dialogMode = "host";
      let previewURLs = [];
      let saveTimer;
      let toastTimer;
      const appearanceKey = "noctweave.publisher.appearance";

      function applyShellTheme(value) {
        const theme = ["system", "light", "dark"].includes(value) ? value : "system";
        document.documentElement.dataset.theme = theme;
        elements.appearanceSelect.value = theme;
        try { localStorage.setItem(appearanceKey, theme); } catch {}
      }

      function restoreShellTheme() {
        let value = "system";
        try { value = localStorage.getItem(appearanceKey) || value; } catch {}
        applyShellTheme(value);
      }

      const defaultProject = () => ({
        publicationID: crypto.randomUUID().toLowerCase(),
        siteLabel: "first-light",
        title: "A quieter place on the network.",
        subtitle: "Signed by its publisher. Carried by replaceable infrastructure.",
        body: "This page is an ordinary HTML, CSS, and JavaScript bundle served through Noctweave Net. Its identity belongs to the publication—not to this relay.",
        accent: "#7c6cff",
        buttonText: "Learn more",
        buttonURL: "https://example.com",
        customCode: false,
        revision: 0,
        previousHostObjectID: null,
        previousCapsuleObjectID: null,
        previousHeadID: null,
        html: "",
        css: "",
        js: ""
      });

      async function start() {
        restoreShellTheme();
        try {
          config = await fetchConfig();
          database = await openDatabase();
          project = await readRecord("projects", PROJECT_KEY) || defaultProject();
          if (!project.html || !project.css || !project.js) generateSource();
          identity = await loadOrCreateIdentity(project.publicationID);
          hostedCopies = normalizeHostingLedger(
            await readRecord("publications", project.publicationID)
          );
          currentHosted = hostedCopies.at(-1) || null;
          currentHostedVerified = currentHosted
            ? await verifyStoredHostingState()
            : false;
          bindEvents();
          writeProjectToUI();
          showFile("html");
          updateIdentityUI();
          updateHostingUI();
          updatePreview();
        } catch (error) {
          console.error(error);
          showToast(safeMessage(error, "Publisher could not start."));
          elements.relayLabel.textContent = "Relay unavailable";
          elements.hostButton.disabled = true;
          return;
        }

        const requestedObject = new URLSearchParams(location.search).get("object");
        if (requestedObject) {
          try {
            await viewHostedObject(requestedObject);
          } catch (error) {
            showHostedObjectFailure(error);
          }
        }
      }

      function showHostedObjectFailure(error) {
        selectPanel("preview");
        elements.previewAddress.textContent = "Hosted copy unavailable";
        updatePreview({
          html: `<main class="unavailable">
            <p>NOCTWEB</p>
            <h1>Hosted copy unavailable.</h1>
            <p>This relay no longer carries the requested object. The publisher workspace remains available.</p>
          </main>`,
          css: `:root { color-scheme: light dark; font-family: system-ui, sans-serif; }
            body { margin: 0; min-height: 100vh; display: grid; place-items: center;
              background: #08080d; color: #f5f4ff; }
            .unavailable { width: min(34rem, calc(100% - 3rem)); }
            .unavailable > p:first-child { color: #9285ff; font-weight: 800;
              letter-spacing: .16em; }
            h1 { margin: .5rem 0; font-size: clamp(2rem, 7vw, 4rem); }
            .unavailable > p:last-child { color: #aaa7b8; line-height: 1.65; }`,
          js: ""
        }, "Hosted object unavailable");
        showToast(safeMessage(error, "Hosted page is unavailable."));
      }

      async function fetchConfig() {
        const response = await fetch("/noctweb/config.json", {
          credentials: "omit",
          cache: "no-store",
          redirect: "error",
          referrerPolicy: "no-referrer"
        });
        if (!response.ok) throw new Error("Relay configuration is unavailable.");
        const value = await response.json();
        if (value.version !== 1 || value.hostModule !== "nw.net-host" ||
            value.hostModuleVersion !== 1 || !/^sha256:[0-9a-f]{64}$/u.test(value.relayNamespaceID) ||
            !/^[a-z0-9][a-z0-9-]{0,31}$/u.test(value.relaySuffix) ||
            typeof value.hostSigningPublicKey !== "string") {
          throw new Error("Relay configuration is invalid.");
        }
        return value;
      }

      function bindEvents() {
        elements.appearanceSelect.addEventListener("change", () => applyShellTheme(elements.appearanceSelect.value));
        document.querySelectorAll("[data-tab]").forEach((button) => {
          button.addEventListener("click", () => selectPanel(button.dataset.tab));
        });
        document.querySelectorAll("[data-file]").forEach((button) => {
          button.addEventListener("click", () => showFile(button.dataset.file));
        });
        const fields = [
          ["siteLabel", "siteLabel"], ["titleInput", "title"], ["subtitleInput", "subtitle"],
          ["bodyInput", "body"], ["accentInput", "accent"], ["buttonTextInput", "buttonText"],
          ["buttonURLInput", "buttonURL"]
        ];
        fields.forEach(([id, key]) => {
          elements[id].addEventListener("input", () => {
            project[key] = key === "siteLabel"
              ? canonicalSiteLabel(elements[id].value)
              : elements[id].value;
            if (key === "siteLabel") elements[id].value = project[key];
            if (!project.customCode) generateSource();
            writeDerivedUI();
            scheduleSave();
            updatePreview();
          });
        });
        elements.codeEditor.addEventListener("input", () => {
          project[currentFile] = elements.codeEditor.value;
          project.customCode = true;
          elements.customCodeNotice.hidden = false;
          scheduleSave();
          updatePreview();
        });
        elements.applyDesignButton.addEventListener("click", () => {
          if (!confirm("Replace index.html, styles.css, and app.js with the current design?")) return;
          project.customCode = false;
          generateSource();
          elements.customCodeNotice.hidden = true;
          showFile(currentFile);
          scheduleSave();
          updatePreview();
        });
        elements.refreshPreviewButton.addEventListener("click", updatePreview);
        elements.resetButton.addEventListener("click", resetProject);
        elements.hostButton.addEventListener("click", () => openDialog("host"));
        elements.unhostButton.addEventListener("click", () => openDialog("release"));
        elements.copyLinkButton.addEventListener("click", copyTestLink);
        elements.hostForm.addEventListener("submit", handleDialogSubmit);
      }

      function selectPanel(name) {
        document.querySelectorAll("[data-tab]").forEach((button) => {
          button.classList.toggle("active", button.dataset.tab === name);
        });
        document.querySelectorAll("[data-panel]").forEach((panel) => {
          panel.classList.toggle("active", panel.dataset.panel === name);
        });
        if (name === "preview") updatePreview();
      }

      function showFile(name) {
        currentFile = name;
        document.querySelectorAll("[data-file]").forEach((button) => {
          button.classList.toggle("active", button.dataset.file === name);
        });
        elements.codeEditor.value = project[name] || "";
        elements.codeEditor.setAttribute("aria-label", `${name} source editor`);
      }

      function writeProjectToUI() {
        elements.siteLabel.value = project.siteLabel;
        elements.titleInput.value = project.title;
        elements.subtitleInput.value = project.subtitle;
        elements.bodyInput.value = project.body;
        elements.accentInput.value = project.accent;
        elements.buttonTextInput.value = project.buttonText;
        elements.buttonURLInput.value = project.buttonURL;
        elements.customCodeNotice.hidden = !project.customCode;
        elements.suffixText.textContent = `.${config.relaySuffix}`;
        elements.relayLabel.textContent = `Host ${config.relaySuffix} · nw.net-host@1`;
        writeDerivedUI();
      }

      function writeDerivedUI() {
        elements.accentValue.textContent = project.accent;
        elements.previewAddress.textContent = provisionalAddress();
      }

      function generateSource() {
        const title = escapeHTML(project.title);
        const subtitle = escapeHTML(project.subtitle);
        const body = escapeHTML(project.body).replaceAll("\n", "<br>");
        const button = safeHTTPURL(project.buttonURL)
          ? `<a class="site-button" href="${escapeAttribute(project.buttonURL)}" target="_blank" rel="noreferrer">${escapeHTML(project.buttonText)}</a>`
          : "";
        project.html = `<main class="site-shell">
      <p class="site-kicker">NOCTWEB</p>
      <h1>${title}</h1>
      <p class="site-subtitle">${subtitle}</p>
      <div class="site-body">${body}</div>
      ${button}
    </main>`;
        project.css = `:root {
      color: #f7f7fb;
      background: #0a0b10;
      font-family: Inter, ui-sans-serif, system-ui, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 32px;
      background:
        radial-gradient(circle at 20% 0%, ${project.accent}33, transparent 34rem),
        #0a0b10;
    }
    .site-shell { width: min(760px, 100%); }
    .site-kicker { color: ${project.accent}; font-size: 12px; font-weight: 800; letter-spacing: .2em; }
    h1 { margin: 12px 0; font-size: clamp(42px, 9vw, 86px); line-height: .96; letter-spacing: -.055em; }
    .site-subtitle { max-width: 650px; color: #b5b8c4; font-size: clamp(18px, 3vw, 25px); line-height: 1.45; }
    .site-body { max-width: 620px; margin: 34px 0; color: #d9dbe3; line-height: 1.75; }
    .site-button { display: inline-flex; padding: 13px 18px; border-radius: 10px; background: ${project.accent}; color: white; font-weight: 750; text-decoration: none; }`;
        project.js = `document.documentElement.dataset.noctwebReady = "true";`;
      }

      function updatePreview(files = project, verification = "Local draft · sandboxed") {
        for (const url of previewURLs) URL.revokeObjectURL(url);
        previewURLs = [];
        const cssURL = URL.createObjectURL(new Blob([files.css || ""], { type: "text/css" }));
        const jsURL = URL.createObjectURL(new Blob([files.js || ""], { type: "text/javascript" }));
        previewURLs.push(cssURL, jsURL);
        const parsed = new DOMParser().parseFromString(files.html || "", "text/html");
        const markup = parsed.body?.innerHTML || "";
        const childCSP = [
          "default-src 'none'", "img-src data: blob:", "media-src data: blob:",
          "font-src data:", "style-src blob: 'unsafe-inline'", "script-src blob:",
          "connect-src 'none'", "frame-src 'none'", "object-src 'none'",
          "base-uri 'none'", "form-action 'none'"
        ].join("; ");
        elements.previewFrame.srcdoc = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="${escapeAttribute(childCSP)}"><link rel="stylesheet" href="${cssURL}"></head><body>${markup}<script src="${jsURL}"><\/script></body></html>`;
        elements.verificationState.textContent = verification;
      }

      async function loadOrCreateIdentity(publicationID) {
        const existing = await readRecord("identities", publicationID);
        if (existing?.privateKey && existing?.publicKey && existing?.releaseVaultKey) return existing;
        const signingKeys = await crypto.subtle.generateKey(
          { name: "Ed25519" },
          false,
          ["sign", "verify"]
        );
        if (signingKeys.privateKey.extractable) {
          throw new Error("Publisher private key must be non-extractable.");
        }
        const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", signingKeys.publicKey));
        const publisherID = await makePublisherID(publicKey);
        const releaseVaultKey = await crypto.subtle.generateKey(
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"]
        );
        const value = {
          publicationID,
          privateKey: signingKeys.privateKey,
          publicKey: publicKey.buffer,
          publisherID,
          releaseVaultKey
        };
        await writeRecord("identities", value);
        return value;
      }

      function updateIdentityUI() {
        elements.publisherShort.textContent = shortID(identity.publisherID);
        elements.identityChip.title = identity.publisherID;
      }

      function openDialog(mode) {
        dialogMode = mode;
        elements.dialogError.textContent = "";
        elements.passwordInput.value = "";
        const releasing = mode === "release";
        elements.dialogTitle.textContent = releasing
          ? hostedCopies.length > 1
            ? `Unhost ${hostedCopies.length} relay copies`
            : "Unhost this relay copy"
          : "Host this revision";
        elements.dialogDescription.textContent = releasing
          ? "This releases every revision tracked for this publication at this relay. It cannot erase copies hosted elsewhere."
          : "The publisher key stays in this browser. The password authorizes only this relay write and is not saved.";
        elements.retentionField.hidden = releasing;
        elements.dialogSubmit.textContent = releasing
          ? hostedCopies.length > 1
            ? "Unhost all copies"
            : "Unhost copy"
          : "Host revision";
        elements.dialogSubmit.className = releasing ? "button danger" : "button primary";
        elements.hostDialog.showModal();
        queueMicrotask(() => elements.passwordInput.focus());
      }

      async function handleDialogSubmit(event) {
        const submitter = event.submitter;
        if (submitter?.value === "cancel") return;
        event.preventDefault();
        if (!elements.hostForm.reportValidity()) return;
        elements.dialogSubmit.disabled = true;
        elements.dialogError.textContent = "";
        let password = elements.passwordInput.value;
        elements.passwordInput.value = "";
        try {
          if (dialogMode === "release") await releaseHostedCopy(password);
          else await hostRevision(password);
          elements.hostDialog.close();
        } catch (error) {
          elements.dialogError.textContent = safeMessage(error, "Relay operation failed.");
        } finally {
          password = "";
          elements.dialogSubmit.disabled = false;
        }
      }

      async function hostRevision(password) {
        if (hostedCopies.length >= MAX_TRACKED_HOSTED_COPIES) {
          throw new Error("Unhost tracked revisions before hosting another copy.");
        }
        const publicKey = new Uint8Array(identity.publicKey);
        const revision = Number(project.revision || 0) + 1;
        const publicationID = project.publicationID.toLowerCase();
        const address = provisionalAddress();
        const files = [
          { path: "app.js", mediaType: "text/javascript; charset=utf-8", bytes: toBase64(encoder.encode(project.js)) },
          { path: "index.html", mediaType: "text/html; charset=utf-8", bytes: toBase64(encoder.encode(project.html)) },
          { path: "styles.css", mediaType: "text/css; charset=utf-8", bytes: toBase64(encoder.encode(project.css)) }
        ].sort((left, right) => left.path.localeCompare(right.path, "en", { sensitivity: "variant" }));
        const object = {
          protocolVersion: PROTOCOL_VERSION,
          publicationID,
          address,
          relayNamespaceID: config.relayNamespaceID,
          routeDirective: "open",
          publisherID: identity.publisherID,
          revision,
          ...(project.previousCapsuleObjectID
            ? { previousObjectID: project.previousCapsuleObjectID }
            : {}),
          title: project.title,
          subtitle: project.subtitle,
          body: project.body,
          accentHex: project.accent,
          bundle: {
            entryPath: "index.html",
            files
          }
        };
        const encodedObject = encoder.encode(canonicalJSON(object));
        const capsuleObjectID = `sha256:${hex(await sha256(encodedObject))}`;
        const claims = {
          protocolVersion: PROTOCOL_VERSION,
          publicationID,
          address,
          relayNamespaceID: config.relayNamespaceID,
          routeDirective: "open",
          publisherID: identity.publisherID,
          publisherPublicKey: toBase64(publicKey),
          objectID: capsuleObjectID,
          revision,
          ...(project.previousHeadID ? { previousHeadID: project.previousHeadID } : {}),
          issuedAtMilliseconds: Date.now()
        };
        const signaturePayload = publisherHeadPayload(claims);
        const signature = new Uint8Array(await crypto.subtle.sign(
          { name: "Ed25519" },
          identity.privateKey,
          signaturePayload
        ));
        const head = { claims, signature: toBase64(signature) };
        const headID = await publisherHeadID(signaturePayload, signature);
        const envelopeBytes = encoder.encode(canonicalJSON({
          profile: CAPSULE_PROFILE,
          object,
          encodedObject: toBase64(encodedObject),
          head,
          headID
        }));
        if (envelopeBytes.byteLength > config.maximumObjectBytes) {
          throw new Error(`Signed site exceeds the relay's ${config.maximumObjectBytes}-byte object limit.`);
        }
        const objectID = hex(await sha256(envelopeBytes));
        const releaseCapability = randomBytes(32);
        const releaseDigest = await sha256(domainPayload(RELEASE_DOMAIN, releaseCapability));
        const idempotencyKey = randomBytes(32);
        const previousObjectID = project.previousHostObjectID;
        const ttlSeconds = Number(elements.retentionInput.value);
        const relayResponse = await relayRequest("put", {
          objectID,
          payload: toBase64(envelopeBytes),
          ttlSeconds,
          releaseCapabilityDigest: toBase64(releaseDigest),
          idempotencyKey: toBase64(idempotencyKey)
        }, password);
        const receipt = relayResponse.body?.receipt;
        await verifyHostingReceipt(receipt, objectID, envelopeBytes.byteLength);
        try {
          const bindingResponse = await relayRequest("bind", {
            version: 1,
            relaySuffix: `.${config.relaySuffix}`,
            siteLabel: canonicalSiteLabel(project.siteLabel),
            objectID,
            publisherID: identity.publisherID,
            headID,
            revision,
            previousObjectID,
            idempotencyKey: toBase64(randomBytes(32))
          }, password);
          verifyNameBinding(bindingResponse.body?.nameResolution, {
            relaySuffix: `.${config.relaySuffix}`,
            siteLabel: canonicalSiteLabel(project.siteLabel),
            objectID,
            publisherID: identity.publisherID,
            headID,
            revision
          });
        } catch (error) {
          try {
            await relayRequest("release", {
              objectID,
              releaseCapability: toBase64(releaseCapability)
            }, password);
          } catch {
            // The object is still bounded by its requested relay retention.
          }
          throw new Error(`Name binding failed: ${safeMessage(error, "Relay operation failed.")}`);
        }
        const protectedRelease = await protectReleaseCapability(releaseCapability);
        const hostedCopy = {
          publicationID,
          objectID,
          address,
          publisherID: identity.publisherID,
          headID,
          capsuleObjectID,
          receipt,
          protectedRelease
        };
        hostedCopies.push(hostedCopy);
        currentHosted = hostedCopy;
        currentHostedVerified = true;
        await persistHostingLedger();
        project.revision = revision;
        project.previousHostObjectID = objectID;
        project.previousCapsuleObjectID = capsuleObjectID;
        project.previousHeadID = headID;
        await persistProject();
        updateHostingUI();
        showToast("Revision hosted, named, and receipt verified.");
      }

      async function releaseHostedCopy(password) {
        if (!hostedCopies.length) throw new Error("There is no hosted relay copy to release.");
        const retained = [];
        let cleared = 0;
        let releaseError = null;
        for (let index = 0; index < hostedCopies.length; index += 1) {
          const copy = hostedCopies[index];
          let capability;
          try {
            capability = await unprotectReleaseCapability(copy.protectedRelease);
            const relayResponse = await relayRequest("release", {
              objectID: copy.objectID,
              releaseCapability: toBase64(capability)
            }, password);
            const release = relayResponse.body?.release;
            if (release?.objectID !== copy.objectID ||
                typeof release.released !== "boolean") {
              throw new Error("Relay returned an invalid release receipt.");
            }
            cleared += 1;
          } catch (error) {
            releaseError = error;
            retained.push(...hostedCopies.slice(index));
            break;
          } finally {
            capability?.fill(0);
          }
        }
        if (releaseError && cleared === 0) throw releaseError;
        hostedCopies = retained;
        currentHosted = hostedCopies.at(-1) || null;
        currentHostedVerified = false;
        await persistHostingLedger();
        updateHostingUI();
        showToast(hostedCopies.length
          ? `${cleared} relay ${cleared === 1 ? "copy was" : "copies were"} removed; ${hostedCopies.length} remain tracked.`
          : `${cleared} relay ${cleared === 1 ? "copy was" : "copies were"} removed.`);
      }

      function normalizeHostingLedger(value) {
        if (!value) return [];
        const copies = Array.isArray(value.copies) ? value.copies : [value];
        if (value.publicationID !== project.publicationID ||
            copies.length < 1 || copies.length > MAX_TRACKED_HOSTED_COPIES) {
          throw new Error("Stored hosting history is invalid.");
        }
        const objectIDs = new Set();
        for (const copy of copies) {
          if (!copy || copy.publicationID !== project.publicationID ||
              copy.publisherID !== identity.publisherID ||
              typeof copy.address !== "string" ||
              !/^[0-9a-f]{64}$/u.test(copy.objectID) ||
              objectIDs.has(copy.objectID) ||
              !copy.receipt || !copy.protectedRelease) {
            throw new Error("Stored hosting history is invalid.");
          }
          objectIDs.add(copy.objectID);
        }
        return copies;
      }

      async function persistHostingLedger() {
        if (!hostedCopies.length) {
          await deleteRecord("publications", project.publicationID);
          return;
        }
        await writeRecord("publications", {
          version: 1,
          publicationID: project.publicationID,
          copies: hostedCopies
        });
      }

      async function verifyStoredHostingState() {
        try {
          if (currentHosted.publicationID !== project.publicationID ||
              currentHosted.publisherID !== identity.publisherID ||
              typeof currentHosted.address !== "string" ||
              !/^[0-9a-f]{64}$/u.test(currentHosted.objectID)) {
            throw new Error("Stored hosting state is not bound to this publication.");
          }
          const byteCount = currentHosted.receipt?.byteCount;
          await verifyHostingReceipt(currentHosted.receipt, currentHosted.objectID, byteCount);
          const response = await relayRequest("has", {
            objectID: currentHosted.objectID
          }, null);
          const presence = response.body?.presence;
          if (!presence ||
              Object.keys(presence).sort().join(",") !== "expiresAt,objectID,present" ||
              presence.objectID !== currentHosted.objectID ||
              typeof presence.present !== "boolean") {
            throw new Error("Relay returned an invalid host-presence response.");
          }
          if (presence.present) {
            timestampSeconds(presence.expiresAt);
          } else if (presence.expiresAt !== null) {
            throw new Error("An absent host object must not claim an expiry.");
          }
          return presence.present;
        } catch {
          return false;
        }
      }

      async function viewHostedObject(objectID) {
        if (!/^[0-9a-f]{64}$/u.test(objectID)) throw new Error("Hosted object ID is invalid.");
        const response = await relayRequest("get", { objectID }, null);
        const hosted = response.body?.object;
        if (!hosted?.payload || !hosted.receipt) throw new Error("Relay returned an invalid hosted object.");
        const envelopeBytes = fromBase64(hosted.payload);
        if (hex(await sha256(envelopeBytes)) !== objectID) throw new Error("Hosted object hash verification failed.");
        await verifyHostingReceipt(hosted.receipt, objectID, envelopeBytes.byteLength);
        const envelope = JSON.parse(decoder.decode(envelopeBytes));
        const files = await verifyPublisherEnvelope(envelope);
        selectPanel("preview");
        elements.previewAddress.textContent = envelope.object.address;
        updatePreview(files, `Verified publisher ${shortID(envelope.object.publisherID)} · Hosted`);
        showToast("Hosted page and publisher signature verified.");
      }

      async function verifyPublisherEnvelope(envelope) {
        const object = envelope?.object;
        const claims = envelope?.head?.claims;
        const bundle = object?.bundle;
        if (!envelope || envelope.profile !== CAPSULE_PROFILE ||
            object?.protocolVersion !== PROTOCOL_VERSION ||
            claims?.protocolVersion !== PROTOCOL_VERSION ||
            object.relayNamespaceID !== config.relayNamespaceID ||
            claims.relayNamespaceID !== config.relayNamespaceID ||
            object.routeDirective !== "open" ||
            claims.routeDirective !== "open" ||
            bundle?.entryPath !== "index.html" ||
            !Array.isArray(bundle.files) || bundle.files.length !== 3) {
          throw new Error("Hosted publisher envelope is invalid.");
        }
        const encodedObject = fromBase64(envelope.encodedObject);
        const decodedObject = JSON.parse(decoder.decode(encodedObject));
        const objectID = `sha256:${hex(await sha256(encodedObject))}`;
        if (canonicalJSON(decodedObject) !== canonicalJSON(object) ||
            encoder.encode(canonicalJSON(decodedObject)).byteLength !== encodedObject.byteLength ||
            canonicalJSON(decodedObject) !== decoder.decode(encodedObject) ||
            claims.objectID !== objectID ||
            claims.publicationID !== object.publicationID ||
            claims.address !== object.address ||
            claims.publisherID !== object.publisherID ||
            claims.revision !== object.revision) {
          throw new Error("Hosted capsule does not match its canonical object.");
        }
        const publicKeyBytes = fromBase64(claims.publisherPublicKey);
        if (publicKeyBytes.byteLength !== 32 ||
            await makePublisherID(publicKeyBytes) !== claims.publisherID) {
          throw new Error("Publisher identity verification failed.");
        }
        const publicKey = await crypto.subtle.importKey(
          "raw", publicKeyBytes, { name: "Ed25519" }, false, ["verify"]
        );
        const signaturePayload = publisherHeadPayload(claims);
        const signature = fromBase64(envelope.head.signature);
        const verified = await crypto.subtle.verify(
          { name: "Ed25519" },
          publicKey,
          signature,
          signaturePayload
        );
        if (!verified) throw new Error("Publisher signature verification failed.");
        if (await publisherHeadID(signaturePayload, signature) !== envelope.headID) {
          throw new Error("Publisher head identifier verification failed.");
        }
        const mapped = {};
        for (const file of bundle.files) {
          if (!["app.js", "index.html", "styles.css"].includes(file.path)) {
            throw new Error("Hosted page contains an unsupported path.");
          }
          const text = decoder.decode(fromBase64(file.bytes));
          if (file.path === "app.js") mapped.js = text;
          if (file.path === "index.html") mapped.html = text;
          if (file.path === "styles.css") mapped.css = text;
        }
        if (typeof mapped.html !== "string" || typeof mapped.css !== "string" || typeof mapped.js !== "string") {
          throw new Error("Hosted page bundle is incomplete.");
        }
        return mapped;
      }

      async function verifyHostingReceipt(receipt, objectID, byteCount) {
        if (!receipt || !/^[0-9a-f]{64}$/u.test(objectID) ||
            !Number.isSafeInteger(byteCount) || byteCount < 1 ||
            byteCount > config.maximumObjectBytes ||
            receipt.objectID !== objectID || receipt.byteCount !== byteCount ||
            receipt.signatureAlgorithm !== "Ed25519" ||
            receipt.signingPublicKey !== config.hostSigningPublicKey) {
          throw new Error("Hosting receipt does not match this relay or object.");
        }
        const stored = timestampSeconds(receipt.storedAt);
        const expires = timestampSeconds(receipt.expiresAt);
        if (expires <= stored || expires - stored > config.maximumRetentionSeconds) {
          throw new Error("Hosting receipt retention is invalid.");
        }
        const key = await crypto.subtle.importKey(
          "raw",
          fromBase64(receipt.signingPublicKey),
          { name: "Ed25519" },
          false,
          ["verify"]
        );
        const message = concatenate(
          encoder.encode("org.noctweave.net/hosting-receipt/v1"),
          Uint8Array.of(0),
          encoder.encode(objectID),
          uint64(byteCount),
          uint64(stored),
          uint64(expires)
        );
        const valid = await crypto.subtle.verify(
          { name: "Ed25519" },
          key,
          fromBase64(receipt.signature),
          message
        );
        if (!valid) throw new Error("Hosting receipt signature verification failed.");
      }

      function verifyNameBinding(resolution, expected) {
        if (!resolution ||
            resolution.version !== 1 ||
            !/^nwr1[0-9a-f]{64}$/u.test(resolution.relayID) ||
            resolution.relaySuffix !== expected.relaySuffix ||
            resolution.siteLabel !== expected.siteLabel ||
            resolution.objectID !== expected.objectID ||
            resolution.publisherID !== expected.publisherID ||
            resolution.headID !== expected.headID ||
            resolution.revision !== expected.revision ||
            resolution.signatureAlgorithm !== "ML-DSA-65" ||
            typeof resolution.signature !== "string") {
          throw new Error("Relay returned an invalid signed name binding.");
        }
      }

      async function relayRequest(method, body, authToken) {
        const requestID = crypto.randomUUID().toUpperCase();
        const request = {
          requestID,
          module: "nw.net-host",
          version: 1,
          method,
          body,
          authToken: authToken || null
        };
        const response = await fetch("/relay", {
          method: "POST",
          headers: { "accept": "application/json", "content-type": "application/json" },
          body: JSON.stringify(request),
          credentials: "omit",
          cache: "no-store",
          redirect: "error",
          referrerPolicy: "no-referrer"
        });
        if (!response.ok) throw new Error(`Relay HTTP request failed (${response.status}).`);
        const value = await response.json();
        if (value.requestID !== requestID || value.module !== request.module ||
            value.version !== 1 || value.method !== method) {
          throw new Error("Relay response correlation failed.");
        }
        if (value.status !== "success") {
          throw new Error(value.error?.message || "Relay rejected the request.");
        }
        return value;
      }

      function updateHostingUI() {
        const hosted = Boolean(currentHosted);
        elements.copyLinkButton.disabled = !currentHostedVerified;
        elements.unhostButton.disabled = !hosted;
        elements.unhostButton.textContent = hostedCopies.length > 1
          ? `Unhost all ${hostedCopies.length} copies`
          : "Unhost copy";
        elements.hostedHeading.textContent = currentHostedVerified
          ? "Hosted · receipt and presence verified"
          : hosted
            ? "Recorded relay copy · verification unavailable"
            : "Not hosted yet";
        elements.hostedDetail.textContent = currentHostedVerified
          ? `${currentHosted.address} · object ${shortID(currentHosted.objectID)}. ${hostedCopies.length} ${hostedCopies.length === 1 ? "revision is" : "revisions are"} tracked at this relay; this is not consensus finality.`
          : hosted
            ? "The local release capability is retained, but this relay did not prove that the copy is still present."
          : "Host a signed revision when it is ready to test through this relay.";
      }

      async function copyTestLink() {
        if (!currentHostedVerified || !currentHosted) return;
        const url = new URL("/noctweb/", location.origin);
        url.searchParams.set("object", currentHosted.objectID);
        await navigator.clipboard.writeText(url.toString());
        showToast("Verified test link copied.");
      }

      async function resetProject() {
        if (!confirm("Reset this local draft? Its publisher identity and any hosted relay copy will remain until explicitly unhosted.")) return;
        const retainedID = project.publicationID;
        project = defaultProject();
        project.publicationID = retainedID;
        generateSource();
        await persistProject();
        writeProjectToUI();
        showFile("html");
        updatePreview();
        showToast("Local draft reset.");
      }

      function provisionalAddress() {
        return `noct://${canonicalSiteLabel(project.siteLabel) || "site"}.${config.relaySuffix}/`;
      }

      async function makePublisherID(publicKey) {
        return `nwpub1_${hex(await sha256(domainPayload(PUBLISHER_ID_DOMAIN, publicKey)))}`;
      }

      async function protectReleaseCapability(capability) {
        const nonce = randomBytes(12);
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: nonce },
          identity.releaseVaultKey,
          capability
        ));
        return { nonce: toBase64(nonce), ciphertext: toBase64(ciphertext) };
      }

      async function unprotectReleaseCapability(value) {
        if (!value?.nonce || !value?.ciphertext) throw new Error("Release capability is unavailable.");
        return new Uint8Array(await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: fromBase64(value.nonce) },
          identity.releaseVaultKey,
          fromBase64(value.ciphertext)
        ));
      }

      function openDatabase() {
        return new Promise((resolve, reject) => {
          const request = indexedDB.open(DB_NAME, DB_VERSION);
          request.onupgradeneeded = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains("projects")) db.createObjectStore("projects");
            if (!db.objectStoreNames.contains("identities")) db.createObjectStore("identities", { keyPath: "publicationID" });
            if (!db.objectStoreNames.contains("publications")) db.createObjectStore("publications", { keyPath: "publicationID" });
          };
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(new Error("Publisher local storage could not open."));
        });
      }

      function readRecord(store, key) {
        return transactionRequest(store, "readonly", (objectStore) => objectStore.get(key));
      }

      function writeRecord(store, value) {
        return transactionRequest(store, "readwrite", (objectStore) => {
          if (store === "projects") return objectStore.put(value, PROJECT_KEY);
          return objectStore.put(value);
        });
      }

      function deleteRecord(store, key) {
        return transactionRequest(store, "readwrite", (objectStore) => objectStore.delete(key));
      }

      function transactionRequest(store, mode, action) {
        return new Promise((resolve, reject) => {
          const tx = database.transaction(store, mode);
          const request = action(tx.objectStore(store));
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(new Error("Publisher local storage operation failed."));
        });
      }

      function scheduleSave() {
        clearTimeout(saveTimer);
        elements.saveState.textContent = "Saving…";
        saveTimer = setTimeout(() => persistProject().catch(console.error), 350);
      }

      async function persistProject() {
        await writeRecord("projects", project);
        elements.saveState.textContent = "Saved locally";
      }

      function canonicalJSON(value) {
        if (value === null || typeof value === "boolean" || typeof value === "string") {
          return JSON.stringify(value);
        }
        if (typeof value === "number") {
          if (!Number.isSafeInteger(value)) throw new Error("Canonical numbers must be safe integers.");
          return String(value);
        }
        if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
        if (value && typeof value === "object") {
          return `{${Object.keys(value).sort().map((key) =>
            `${JSON.stringify(key)}:${canonicalJSON(value[key])}`
          ).join(",")}}`;
        }
        throw new Error("Value is not canonical JSON.");
      }

      function domainPayload(domain, payload) {
        return concatenate(encoder.encode(domain), Uint8Array.of(0), payload);
      }

      function uint32(value) {
        if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
          throw new Error("Transcript field length is invalid.");
        }
        const output = new Uint8Array(4);
        new DataView(output.buffer).setUint32(0, value, false);
        return output;
      }

      function transcriptField(value, maximum) {
        const bytes = typeof value === "string" ? encoder.encode(value) : value;
        if (!(bytes instanceof Uint8Array) || bytes.byteLength > maximum) {
          throw new Error("Publisher transcript field exceeds its bound.");
        }
        return concatenate(uint32(bytes.byteLength), bytes);
      }

      function publisherHeadPayload(claims) {
        const previousHead = claims.previousHeadID
          ? concatenate(Uint8Array.of(1), transcriptField(claims.previousHeadID, 128))
          : Uint8Array.of(0);
        return concatenate(
          transcriptField(SIGNED_HEAD_DOMAIN, 64),
          Uint8Array.of(1),
          transcriptField(claims.protocolVersion, 64),
          transcriptField(claims.publicationID, 64),
          transcriptField(claims.address, 2048),
          transcriptField(claims.relayNamespaceID, 80),
          transcriptField(claims.routeDirective, 32),
          transcriptField(claims.publisherID, 128),
          transcriptField(fromBase64(claims.publisherPublicKey), 32),
          transcriptField(claims.objectID, 128),
          uint64(claims.revision),
          previousHead,
          uint64(claims.issuedAtMilliseconds)
        );
      }

      async function publisherHeadID(signaturePayload, signature) {
        return `sha256:${hex(await sha256(concatenate(
          encoder.encode(HEAD_HASH_DOMAIN),
          Uint8Array.of(0),
          signaturePayload,
          signature
        )))}`;
      }

      function randomBytes(length) {
        const value = new Uint8Array(length);
        crypto.getRandomValues(value);
        return value;
      }

      async function sha256(value) {
        return new Uint8Array(await crypto.subtle.digest("SHA-256", value));
      }

      function uint64(value) {
        let remaining = BigInt(value);
        const output = new Uint8Array(8);
        for (let index = 7; index >= 0; index -= 1) {
          output[index] = Number(remaining & 0xffn);
          remaining >>= 8n;
        }
        return output;
      }

      function timestampSeconds(value) {
        const milliseconds = Date.parse(value);
        if (!Number.isFinite(milliseconds) || milliseconds < 0 || milliseconds % 1000 !== 0) {
          throw new Error("Receipt timestamp is invalid.");
        }
        return milliseconds / 1000;
      }

      function concatenate(...parts) {
        const output = new Uint8Array(parts.reduce((count, part) => count + part.byteLength, 0));
        let offset = 0;
        for (const part of parts) {
          output.set(part, offset);
          offset += part.byteLength;
        }
        return output;
      }

      function toBase64(value) {
        let binary = "";
        const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
        for (let offset = 0; offset < bytes.length; offset += 0x8000) {
          binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
        }
        return btoa(binary);
      }

      function fromBase64(value) {
        if (typeof value !== "string") throw new Error("Expected base64 data.");
        const binary = atob(value);
        const output = Uint8Array.from(binary, (character) => character.charCodeAt(0));
        if (toBase64(output) !== value) throw new Error("Base64 data is not canonical.");
        return output;
      }

      function hex(value) {
        return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
      }

      function canonicalSiteLabel(value) {
        return String(value || "")
          .toLowerCase()
          .replace(/[^a-z0-9-]+/gu, "-")
          .replace(/^-+|-+$/gu, "")
          .replace(/-{2,}/gu, "-")
          .slice(0, 48);
      }

      function safeHTTPURL(value) {
        try {
          const url = new URL(value);
          return url.protocol === "https:" || url.protocol === "http:";
        } catch {
          return false;
        }
      }

      function escapeHTML(value) {
        return String(value).replace(/[&<>"']/gu, (character) => ({
          "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
        })[character]);
      }

      function escapeAttribute(value) {
        return escapeHTML(value).replaceAll("`", "&#96;");
      }

      function shortID(value) {
        return value && value.length > 22
          ? `${value.slice(0, 12)}…${value.slice(-8)}`
          : value || "unavailable";
      }

      function safeMessage(error, fallback) {
        const value = error instanceof Error ? error.message : "";
        return value && value.length <= 240 ? value : fallback;
      }

      function showToast(message) {
        clearTimeout(toastTimer);
        elements.toast.textContent = message;
        elements.toast.classList.add("visible");
        toastTimer = setTimeout(() => elements.toast.classList.remove("visible"), 3200);
      }

      start();
    })();
    """#
}
