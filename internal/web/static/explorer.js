// Navigation de l'arborescence sans rechargement de page.
//
// Amélioration progressive : sans ce script, les liens fonctionnent comme des
// liens ordinaires et la page se recharge. Avec lui, seul le listing est
// remplacé — la position de défilement, les graphes et le journal restent.
//
// Aucune dépendance, aucun code en ligne : la politique de sécurité de la
// console autorise « script-src 'self' » et rien d'autre.
(function () {
  'use strict';
  var wrap = document.getElementById('tree');
  if (!wrap || !window.fetch || !window.history || !history.pushState) return;

  // /host/X?snap=..&path=..  →  /host/X/tree?snap=..&path=..
  function fragmentURL(pageURL) {
    var i = pageURL.indexOf('?');
    var base = i < 0 ? pageURL : pageURL.slice(0, i);
    var qs = i < 0 ? '' : pageURL.slice(i);
    return base + '/tree' + qs;
  }

  function load(pageURL, push) {
    wrap.setAttribute('aria-busy', 'true');
    fetch(fragmentURL(pageURL), {
      credentials: 'same-origin',
      headers: { 'X-Requested-With': 'amarre' }
    })
      .then(function (r) {
        if (!r.ok) throw new Error(r.status);
        return r.text();
      })
      .then(function (html) {
        wrap.innerHTML = html;
        if (push) history.pushState({ u: pageURL }, '', pageURL);
        bind();
      })
      .catch(function () {
        // Repli sans bruit : on laisse le navigateur faire ce qu'il aurait
        // fait sans script. Une navigation lente vaut mieux qu'une page morte.
        window.location.href = pageURL;
      })
      .then(function () {
        wrap.removeAttribute('aria-busy');
      });
  }

  function bind() {
    var links = wrap.querySelectorAll('a[data-nav]');
    for (var i = 0; i < links.length; i++) {
      links[i].addEventListener('click', function (e) {
        // Laisser passer clic-milieu, Ctrl/Cmd-clic : ouvrir dans un onglet
        // reste le comportement attendu.
        if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey) return;
        e.preventDefault();
        load(this.getAttribute('href'), true);
      });
    }
  }

  window.addEventListener('popstate', function (e) {
    if (e.state && e.state.u) load(e.state.u, false);
  });

  history.replaceState({ u: location.pathname + location.search }, '');
  bind();

  // L'arborescence est chargée APRÈS la page : elle coûte plusieurs secondes
  // et n'a pas à retarder l'affichage du reste de la fiche.
  var initial = wrap.getAttribute('data-initial');
  if (initial) {
    wrap.removeAttribute('data-initial');
    load(initial, false);
  }
})();
