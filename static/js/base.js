/* Shared behaviour: theme toggle, count-up numbers, card spotlight, custom cursor, flash messages, scan progress overlay. */
(function () {
  "use strict";
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Theme toggle buttons show the current mode.
  function labelThemeButtons() {
    document.querySelectorAll("[data-theme-toggle]").forEach(function (b) { b.textContent = "Theme: " + window.dgTheme.get(); });
  }
  document.addEventListener("click", function (e) {
    var t = e.target.closest("[data-theme-toggle]");
    if (t) { window.dgTheme.cycle(); labelThemeButtons(); }
    var f = e.target.closest("[data-dismiss-flash]");
    if (f) f.closest(".flash").remove();
  });
  labelThemeButtons();

  // Count-up for stat numbers.
  if (!reduce) {
    document.querySelectorAll(".stat b.num, .score i.num").forEach(function (el) {
      var to = parseInt(el.textContent, 10);
      if (!(to > 0)) return;
      var t0 = performance.now();
      (function step(t) {
        var k = Math.min(1, (t - t0) / 800);
        el.textContent = Math.round(to * (1 - Math.pow(1 - k, 3)));
        if (k < 1) requestAnimationFrame(step);
      })(t0);
    });
  }

  // Card spotlight follows the mouse.
  document.addEventListener("mousemove", function (e) {
    var c = e.target.closest && e.target.closest(".panel, .stat");
    if (!c) return;
    var r = c.getBoundingClientRect();
    c.style.setProperty("--mx", e.clientX - r.left + "px");
    c.style.setProperty("--my", e.clientY - r.top + "px");
  });

  // Custom cursor: fine pointers only, never with reduced motion.
  if (window.matchMedia("(pointer: fine)").matches && !reduce) {
    var root = document.documentElement;
    var mk = function (cls) { var d = document.createElement("div"); d.className = cls; d.setAttribute("aria-hidden", "true"); document.body.appendChild(d); return d; };
    var dot = mk("cur-dot"), ring = mk("cur-ring"), x = 0, y = 0, rx = 0, ry = 0, started = false;
    var loop = function () { rx += (x - rx) * 0.22; ry += (y - ry) * 0.22; ring.style.transform = "translate3d(" + rx + "px," + ry + "px,0)"; requestAnimationFrame(loop); };
    document.addEventListener("mousemove", function (e) {
      x = e.clientX; y = e.clientY;
      dot.style.transform = "translate3d(" + x + "px," + y + "px,0)";
      if (!started) { started = true; rx = x; ry = y; loop(); }
      root.classList.add("cur-on");
      var t = e.target.closest ? e.target : e.target.parentElement;
      var isText = !!t.closest("input:not([type=checkbox]):not([type=radio]), textarea");
      ring.classList.toggle("text", isText);
      ring.classList.toggle("link", !isText && !!t.closest("a, button, summary, select, label, [role=button]"));
    });
    document.addEventListener("mousedown", function () { ring.classList.add("down"); });
    document.addEventListener("mouseup", function () { ring.classList.remove("down"); });
    root.addEventListener("mouseleave", function () { root.classList.remove("cur-on"); });
  }

  // Scan forms show a progress overlay while the server runs the checks.
  var STEPS = ["Resolving address", "Checking HTTPS redirect", "Reading security headers", "Inspecting cookies", "Testing TLS versions", "Comparing with previous scan"];
  document.addEventListener("submit", function (e) {
    var form = e.target.closest("form[data-scan-form]");
    if (!form || e.defaultPrevented) return;
    var overlay = document.getElementById("scanOverlay");
    if (!overlay) return;
    overlay.hidden = false;
    var label = overlay.querySelector("[data-step]"), bar = overlay.querySelector(".dg-progress i"), i = 0;
    var tick = function () { label.textContent = STEPS[Math.min(i, STEPS.length - 1)] + "…"; bar.style.width = Math.min(95, 12 + i * 16) + "%"; i++; };
    tick(); setInterval(tick, 1200);
    form.querySelectorAll("button[type=submit]").forEach(function (b) { b.disabled = true; });
  });
})();
