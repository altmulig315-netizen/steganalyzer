/* ==========================================================================
 * steg-backend.js  —  drop-in bro mellom StegAnalyzer-frontend og lokal backend
 * --------------------------------------------------------------------------
 * Legg til ÉN linje nederst i HTML-en din (før </body>):
 *     <script src="/static/steg-backend.js"></script>
 *
 * Rører IKKE din eksisterende kode. Fester egne lyttere på samme fil-input og
 * drop-sone, og kjører i parallell med klientside-analysen din:
 *   - lett analyse (LSB, QR, entropi ...) -> nettleseren, som før
 *   - tunge verktøy (zsteg/steghide/binwalk/foremost/StegExpose) -> backend
 *
 * Ved backend: server-modus-indikator lyser + "no data leaves your browser"
 * byttes til en ærlig melding. Uten backend (fil:// eller server av): helt
 * stille, klientsiden virker akkurat som nå.
 *
 * Offentlig API (for modul-knapper i HTML-en):
 *     window.StegBackend.available       -> {verktoy: bool}
 *     window.StegBackend.hasFile()       -> bool
 *     window.StegBackend.run(tool, el?)  -> kjør på sist lastede fil, render i el
 * ======================================================================== */
(function () {
  "use strict";

  /* ---- konfig: endre hvis element-ID-ene i HTML-en din er andre ---------- */
  var FILE_INPUT_ID = "file-input"; // <input type="file">  (matcher v3.4.0)
  var DROPZONE_ID = "drop-zone";    // drag-and-drop-sonen    (matcher v3.4.0)
  var RESULTS_ID = "results";       // resultatområde         (matcher v3.4.0)
  var PASSWORD_ID = "password";     // gjenbruker DITT passord-felt (steghide)

  /* Hvilke filtyper hvert verktøy gir mening for -> unngår støy/feil */
  var APPLIES = {
    zsteg: ["png", "bmp"],
    steghide: ["jpg", "jpeg", "bmp", "wav", "au"],
    binwalk: ["*"],
    foremost: ["*"],
    stegexpose: ["png", "bmp"], // tapsfri LSB-deteksjon
  };

  var AVAILABLE = {};   // fylles fra /api/tools
  var LAST_FILE = null; // sist lastede fil (for modul-knapper)
  var panel = null;

  /* Offentlig API — eksponeres tidlig så modul-kode ikke kræsjer. */
  var PUBLIC = {
    available: AVAILABLE,
    hasFile: function () { return !!LAST_FILE; },
    run: function (tool, el) { if (LAST_FILE) runTool(tool, LAST_FILE, el || null); },
  };
  window.StegBackend = PUBLIC;

  /* ---- småting ---------------------------------------------------------- */
  function ext(name) {
    var m = /\.([a-z0-9]+)$/i.exec(name || "");
    return m ? m[1].toLowerCase() : "";
  }
  function applies(tool, name) {
    var a = APPLIES[tool] || ["*"];
    return a.indexOf("*") !== -1 || a.indexOf(ext(name)) !== -1;
  }
  function esc(s) {
    return String(s).replace(/[&<>]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c];
    });
  }

  /* ---- UI (minimalt, mørkt – restyle gjerne så det matcher temaet ditt) -- */
  function ensurePanel() {
    if (panel) return panel;
    panel = document.createElement("div");
    panel.id = "backend-panel";
    panel.style.cssText = "margin:1.5rem 0;font-family:inherit";
    panel.innerHTML =
      '<h2 style="margin:0 0 .4rem;font-size:1.1rem">\u{1F527} Backend-verktøy ' +
      '<span id="backend-indicator" style="font-size:.72rem;font-weight:600"></span></h2>' +
      '<div id="backend-status" style="font-size:.78rem;opacity:.7;margin-bottom:.5rem"></div>' +
      '<div id="backend-cards"></div>';
    var host = document.getElementById(RESULTS_ID);
    if (host && host.parentNode) {
      host.parentNode.insertBefore(panel, host.nextSibling);
    } else {
      document.body.appendChild(panel);
    }
    return panel;
  }
  function setIndicator(on) {
    ensurePanel();
    var el = document.getElementById("backend-indicator");
    if (on) {
      el.textContent = "\u25CF Server-modus aktiv";
      el.style.color = "#4ade80";
    } else {
      el.textContent = "";
    }
  }
  function setStatus(msg) {
    ensurePanel();
    document.getElementById("backend-status").textContent = msg;
  }
  function cardFor(tool) {
    ensurePanel();
    var el = document.getElementById("bc-" + tool);
    if (!el) {
      el = document.createElement("div");
      el.id = "bc-" + tool;
      el.style.cssText =
        "border:1px solid #333;border-radius:8px;padding:.7rem .8rem;" +
        "margin:.5rem 0;background:#111;color:#ddd;" +
        "font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.8rem";
      document.getElementById("backend-cards").appendChild(el);
    }
    return el;
  }
  /* CLI-ekvivalent per verktøy — vises over hvert backend-resultat */
  var CMD = {
    zsteg: function (f) { return "zsteg -a " + f; },
    steghide: function (f) { return 'steghide extract -sf ' + f + ' -p ""'; },
    binwalk: function (f) { return "binwalk -e " + f; },
    foremost: function (f) { return "foremost -i " + f + " -o out/"; },
    stegexpose: function () { return "java -jar StegExpose.jar <mappe>"; },
  };
  function cmdLine(tool) {
    if (!CMD[tool]) return "";
    var f = (LAST_FILE && LAST_FILE.name) ? LAST_FILE.name : "<fil>";
    return '<div style="color:#7dd3fc;opacity:.8;font-size:.75rem;margin:.2rem 0 .4rem;' +
      'font-family:ui-monospace,Menlo,Consolas,monospace">$ ' + esc(CMD[tool](f)) + "</div>";
  }
  function buildHtml(tool, state, data) {
    if (state === "running") {
      return "<strong>" + tool + "</strong> \u2014 kjører\u2026" + cmdLine(tool);
    }
    var ok = data && data.ok;
    var html =
      "<strong>" + tool + "</strong> " +
      (ok
        ? '<span style="color:#4ade80">\u2713</span>'
        : '<span style="color:#f87171">\u2717</span>') +
      cmdLine(tool) +
      '<pre style="white-space:pre-wrap;word-break:break-word;margin:.4rem 0 0">' +
      esc((data && data.output) || "(ingen output)") +
      "</pre>";
    if (data && data.download) {
      var n = data.files ? data.files.length : "?";
      html +=
        '<a href="' + data.download + '" ' +
        'style="display:inline-block;margin-top:.6rem;padding:.35rem .75rem;' +
        "background:#2563eb;color:#fff;border-radius:6px;text-decoration:none;" +
        'font-size:.78rem">\u2B07 Last ned utpakkede filer (' + n + ")</a>";
    }
    return html;
  }
  function renderResult(tool, state, data, target) {
    var el = target || cardFor(tool);
    el.innerHTML = buildHtml(tool, state, data);
  }

  /* ---- ærlig personvern-tekst i server-modus ---------------------------- */
  function markServerMode() {
    setIndicator(true);
    var claims = document.querySelectorAll(".privacy-claim");
    for (var i = 0; i < claims.length; i++) {
      claims[i].textContent =
        "Server-modus aktiv \u2014 tunge verktøy kjører på din lokale backend; filene sendes dit.";
      claims[i].style.color = "var(--yellow, #e5c07b)";
    }
  }

  /* ---- kjør ett verktøy (target = valgfritt element å rendre i) --------- */
  function runTool(tool, file, target) {
    renderResult(tool, "running", null, target);
    var fd = new FormData();
    fd.append("file", file);
    fd.append("tool", tool);
    if (tool === "steghide") {
      // Gjenbruk det eksisterende #password-feltet ditt (tomt = prøv uten passord).
      var pw = document.getElementById(PASSWORD_ID);
      fd.append("passphrase", pw ? pw.value.trim() : "");
    }
    fetch("/api/analyze", { method: "POST", body: fd })
      .then(function (r) { return r.json(); })
      .then(function (data) { renderResult(tool, "done", data, target); })
      .catch(function (e) {
        renderResult(tool, "done", { ok: false, output: "Nettverksfeil: " + e.message }, target);
      });
  }

  /* ---- auto-dispatch ved ny fil ----------------------------------------- */
  function onFile(file) {
    if (!file) return;
    LAST_FILE = file;
    ensurePanel();
    Object.keys(AVAILABLE).forEach(function (tool) {
      if (AVAILABLE[tool] && applies(tool, file.name)) runTool(tool, file);
    });
  }

  function attach() {
    var input = document.getElementById(FILE_INPUT_ID);
    if (input) {
      input.addEventListener("change", function () {
        if (input.files && input.files[0]) onFile(input.files[0]);
      });
    }
    var dz = document.getElementById(DROPZONE_ID);
    if (dz) {
      dz.addEventListener("drop", function (e) {
        if (e.dataTransfer && e.dataTransfer.files[0]) onFile(e.dataTransfer.files[0]);
      });
    }
    if (!input && !dz) {
      setStatus("Fant ikke #" + FILE_INPUT_ID + " eller #" + DROPZONE_ID +
                " \u2014 juster ID-ene øverst i steg-backend.js.");
    }
  }

  /* ---- init: finnes backend? -------------------------------------------- */
  document.addEventListener("DOMContentLoaded", function () {
    fetch("/api/tools")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        AVAILABLE = d.tools || {};
        PUBLIC.available = AVAILABLE; // hold API-et synkront
        markServerMode();
        var on = [], off = [];
        Object.keys(AVAILABLE).forEach(function (t) {
          (AVAILABLE[t] ? on : off).push(t);
        });
        setStatus(
          "Tilgjengelig: " + (on.join(", ") || "ingen") +
          (off.length ? "   \u2022   mangler: " + off.join(", ") : "")
        );
        attach();
      })
      .catch(function () {
        /* ingen backend -> stille. Klientsiden virker akkurat som før. */
      });
  });
})();
