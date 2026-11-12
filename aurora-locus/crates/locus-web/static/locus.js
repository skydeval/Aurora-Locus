// The console's one script. Without it every page works the same: forms
// post and redirect, status pages refresh on reload.
(function () {
  "use strict";
  if (!window.fetch || !window.DOMParser) {
    return;
  }

  function parse(text) {
    return new DOMParser().parseFromString(text, "text/html");
  }

  // Swaps in a fetched page's parts that this page has too: live status
  // parts, and any marked to follow a change made elsewhere on the page.
  function swapParts(doc, skip) {
    var parts = doc.querySelectorAll("[data-live-part], [data-follows]");
    for (var i = 0; i < parts.length; i++) {
      var old = parts[i].id && document.getElementById(parts[i].id);
      if (old && old !== skip && !(skip && skip.contains(old))) {
        old.replaceWith(document.importNode(parts[i], true));
      }
    }
  }

  // Live status pages: when the server says the page changed, fetch it
  // again and swap in its live parts (cards and tables), leaving forms alone.
  var main = document.querySelector("main[data-live]");
  if (main && window.EventSource) {
    var busy = false;
    var refresh = function () {
      if (busy) {
        return;
      }
      busy = true;
      fetch(window.location.href, { credentials: "same-origin", cache: "no-store" })
        .then(function (r) {
          return r.ok ? r.text() : null;
        })
        .then(function (text) {
          if (text) {
            swapParts(parse(text), null);
          }
        })
        .catch(function () {})
        .then(function () {
          busy = false;
        });
    };
    var events = new EventSource(main.getAttribute("data-live"));
    events.addEventListener("change", refresh);
    events.addEventListener("end", function () {
      events.close();
    });
  }

  // Asks before a removal (`data-confirm` on its form), with or without the
  // live save below.
  document.addEventListener(
    "submit",
    function (e) {
      var q = e.target.getAttribute && e.target.getAttribute("data-confirm");
      if (q && !window.confirm(q)) {
        e.preventDefault();
        e.stopImmediatePropagation();
      }
    },
    true
  );

  // Live saving: a form inside a section (`data-section`, with an id) posts
  // in the background, and the section is replaced by its new state from
  // the page the server answers with, notices and errors moved into it.
  // What the server sends elsewhere (a new item's page, the list after a
  // removal) is followed as an ordinary navigation.
  function noticesOf(doc) {
    var main = doc.querySelector("main");
    var out = [];
    if (!main) {
      return out;
    }
    for (var c = main.firstElementChild; c; c = c.nextElementSibling) {
      if (c.classList.contains("banner") && c.hasAttribute("role")) {
        out.push(c);
      }
    }
    return out;
  }

  // Puts back what was typed (not secrets) into a re-rendered section.
  function keepTyped(section, data) {
    data.forEach(function (value, name) {
      if (typeof value !== "string") {
        return;
      }
      var fields = section.querySelectorAll("[name]");
      for (var i = 0; i < fields.length; i++) {
        var f = fields[i];
        if (f.name !== name || f.type === "password" || f.type === "hidden" || f.type === "file") {
          continue;
        }
        if (f.type === "checkbox" || f.type === "radio") {
          continue;
        }
        f.value = value;
      }
    });
  }

  function navigate(r, text) {
    if (r.redirected) {
      window.location.assign(r.url);
    } else {
      document.open();
      document.write(text);
      document.close();
    }
  }

  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (e.defaultPrevented || !form.closest || (form.method || "").toLowerCase() !== "post") {
      return;
    }
    var section = form.closest("[data-section]");
    if (!section || !section.id || form.hasAttribute("data-full")) {
      return;
    }
    e.preventDefault();
    var data = new FormData(form);
    if (e.submitter && e.submitter.name) {
      data.append(e.submitter.name, e.submitter.value);
    }
    var multipart = (form.enctype || "").toLowerCase() === "multipart/form-data";
    var buttons = form.querySelectorAll("button");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].disabled = true;
    }
    section.setAttribute("aria-busy", "true");
    fetch(form.action, {
      method: "POST",
      body: multipart ? data : new URLSearchParams(data),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "follow",
    }).then(
      function (r) {
        r.text().then(function (text) {
          try {
            apply({ r: r, text: text });
          } catch (err) {
            // It was saved (or refused); show the server's page as is.
            navigate(r, text);
          }
        });
      },
      function () {
        // Never reached the server: post it the ordinary way.
        form.submit();
      }
    );

    function apply(res) {
      var doc = parse(res.text);
      var fresh = doc.getElementById(section.id);
      var moved =
        res.r.redirected && new URL(res.r.url).pathname !== window.location.pathname;
      if (!fresh || moved) {
        navigate(res.r, res.text);
        return;
      }
      var notices = noticesOf(doc);
      if (!notices.length && res.r.ok) {
        var saved = doc.createElement("div");
        saved.className = "banner ok";
        saved.setAttribute("role", "status");
        saved.textContent = "Saved.";
        notices.push(saved);
      }
      for (var n = notices.length - 1; n >= 0; n--) {
        fresh.insertBefore(notices[n], fresh.firstChild);
      }
      var next = document.importNode(fresh, true);
      if (!res.r.ok) {
        keepTyped(next, data);
      }
      section.replaceWith(next);
      swapParts(doc, next);
      // Clear the page's own notices: they belonged to the last load.
      var stale = noticesOf(document);
      for (var s = 0; s < stale.length; s++) {
        stale[s].remove();
      }
      var focus = next.querySelector("[role=alert], [role=status]");
      if (focus) {
        focus.setAttribute("tabindex", "-1");
        focus.focus({ preventScroll: true });
      }
    }
  });
})();
