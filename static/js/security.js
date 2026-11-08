/* Security page: copy recovery codes to the clipboard. */
(function () {
  "use strict";
  var btn = document.querySelector("[data-copy-codes]");
  if (!btn) return;
  btn.addEventListener("click", function () {
    var text = Array.prototype.map.call(document.querySelectorAll(".codes li"), function (li) { return li.textContent.trim(); }).join("\n");
    var ok = function () { btn.textContent = "Copied"; setTimeout(function () { btn.textContent = "Copy all codes"; }, 1500); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(ok, function () { btn.textContent = "Select and copy"; });
    else btn.textContent = "Select and copy";
  });
})();
