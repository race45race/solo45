// A collapse tab on every card: the first heading stays, the rest folds away. Remembered per browser.
(function () {
  const KEY = "solo45-collapsed";
  const page = location.pathname.includes("odds") ? "odds" : "main";
  let shut = {};
  try { shut = JSON.parse(localStorage.getItem(KEY) || "{}") || {}; } catch (e) {}
  const save = () => { try { localStorage.setItem(KEY, JSON.stringify(shut)); } catch (e) {} };

  const css = document.createElement("style");
  css.textContent = `
.card-head { display: flex; align-items: baseline; gap: 8px; }
.collapse-tab { margin-left: auto; flex: none; align-self: flex-start; width: 26px; height: 22px; padding: 0; font: inherit;
  font-size: 11px; line-height: 1; border: 1px solid var(--line); border-radius: 6px; background: var(--panel-2);
  color: var(--muted); cursor: pointer; }
.collapse-tab:hover { color: var(--text); }
.collapse-tab:focus-visible { outline: 2px solid var(--solo45, currentColor); outline-offset: 1px; }
.card.collapsed { align-self: start; }
.card.collapsed > :not(.card-head) { display: none !important; }
.card.collapsed > .card-head { margin-bottom: 0; }
@media (pointer: coarse) { .collapse-tab { width: 34px; height: 28px; } }`;
  document.head.appendChild(css);

  document.querySelectorAll(".card").forEach(card => {
    const head = [...card.children].find(el => el.tagName === "H2" || el.classList.contains("label"));
    if (!head) return;
    const name = (head.firstChild && head.firstChild.textContent || "").trim();
    const key = page + ":" + (card.id || name);
    const tab = document.createElement("button");
    tab.type = "button";
    tab.className = "collapse-tab";
    const show = closed => {
      card.classList.toggle("collapsed", closed);
      tab.textContent = closed ? "▸" : "▾";
      tab.title = (closed ? "Open " : "Collapse ") + name;
      tab.setAttribute("aria-label", tab.title);
      tab.setAttribute("aria-expanded", String(!closed));
    };
    tab.onclick = () => {
      const closed = !card.classList.contains("collapsed");
      if (closed) shut[key] = 1; else delete shut[key];
      save();
      show(closed);
    };
    head.classList.add("card-head");
    head.appendChild(tab);
    show(!!shut[key]);
  });
})();
