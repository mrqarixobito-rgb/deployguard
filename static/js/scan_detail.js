/* Scan detail page: "Explain with AI" (server call, key stays on the server) and copy buttons. */
(function () {
  "use strict";
  var tokenInput = document.querySelector("#csrfHolder input[name=csrfmiddlewaretoken]");

  function box(text, source) {
    var d = document.createElement("div");
    d.className = "ai-box";
    var tag = document.createElement("div");
    tag.className = "ai-tag";
    tag.textContent = source === "gemini" ? "Gemini explanation" : "Sample explanation (no AI key is connected)";
    d.appendChild(tag);
    d.appendChild(document.createTextNode(text));
    return d;
  }

  document.addEventListener("click", function (e) {
    var ex = e.target.closest("[data-explain]");
    if (ex) {
      var slot = ex.closest(".ai-slot");
      slot.innerHTML = '<div class="ai-box"><div class="ai-tag">Thinking…</div><div class="stack" style="gap:8px"><div class="skel" style="width:80%"></div><div class="skel" style="width:95%"></div><div class="skel" style="width:60%"></div></div></div>';
      fetch(slot.dataset.url, { method: "POST", headers: { "X-CSRFToken": tokenInput ? tokenInput.value : "" }, credentials: "same-origin" })
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          slot.innerHTML = "";
          if (res.ok) slot.appendChild(box(res.j.text, res.j.source));
          else slot.textContent = res.j.error || "The explanation could not be created. Try again.";
        })
        .catch(function () { slot.textContent = "The explanation could not be created. Check your connection and try again."; });
      return;
    }
    var cp = e.target.closest("[data-copy]");
    if (cp) {
      var text = cp.closest(".codewrap").querySelector("pre").textContent;
      var done = function () { var old = cp.textContent; cp.textContent = "Copied"; setTimeout(function () { cp.textContent = old; }, 1500); };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function () { cp.textContent = "Select and copy"; });
      else cp.textContent = "Select and copy";
    }
  });
})();
