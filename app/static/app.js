// Progressive enhancement only - every page works without JS.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-tabs]").forEach((tabs) => {
    tabs.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-tab]");
      if (!btn) return;
      tabs.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === btn));
      document.querySelectorAll("[data-panel]").forEach((p) => p.classList.toggle("hidden", p.dataset.panel !== btn.dataset.tab));
    });
  });
  document.querySelectorAll("[data-sevfilter]").forEach((bar) => {
    bar.addEventListener("click", (e) => {
      const chip = e.target.closest("[data-sev]");
      if (!chip) return;
      bar.querySelectorAll(".chip").forEach((c) => c.classList.toggle("active", c === chip));
      document.querySelectorAll(".finding").forEach((f) => {
        f.classList.toggle("hidden", chip.dataset.sev !== "all" && f.dataset.sev !== chip.dataset.sev);
      });
    });
  });
  document.querySelectorAll("[data-filter]").forEach((input) => {
    input.addEventListener("input", () => {
      const q = input.value.toLowerCase();
      document.querySelectorAll(input.dataset.filter).forEach((row) => row.classList.toggle("hidden", !row.textContent.toLowerCase().includes(q)));
    });
  });
  document.querySelectorAll("form[data-confirm]").forEach((f) => f.addEventListener("submit", (e) => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));
  document.querySelectorAll("[data-print]").forEach((b) => b.addEventListener("click", () => { document.querySelectorAll(".finding").forEach((d) => d.open = true); window.print(); }));
});
