/* Loaded in <head> so the saved theme is applied before first paint (no flash). */
(function () {
  var root = document.documentElement;
  function apply(mode) {
    if (mode === "light" || mode === "dark") {
      root.setAttribute("data-theme", mode);
      root.setAttribute("data-bs-theme", mode);
    } else {
      root.removeAttribute("data-theme");
      root.setAttribute("data-bs-theme", window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    }
  }
  var saved = "auto";
  try { saved = localStorage.getItem("dg_theme") || "auto"; } catch (e) { /* storage blocked */ }
  apply(saved);
  window.dgTheme = {
    get: function () { try { return localStorage.getItem("dg_theme") || "auto"; } catch (e) { return "auto"; } },
    cycle: function () {
      var order = ["auto", "light", "dark"], next = order[(order.indexOf(this.get()) + 1) % 3];
      try { localStorage.setItem("dg_theme", next); } catch (e) { /* ignore */ }
      apply(next);
      return next;
    }
  };
})();
