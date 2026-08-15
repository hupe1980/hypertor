// Colour scheme toggle and documentation search.
//
// No framework and no search library: Zola emits the index as JSON, and ranking
// a few dozen documentation pages needs far less code than pulling in a
// dependency to do it. The whole file is a few kilobytes and the site works
// without it — search is progressive enhancement, not the navigation.

(function () {
  'use strict';

  // -------------------------------------------------------------------------
  // Colour scheme
  // -------------------------------------------------------------------------

  var root = document.documentElement;
  var toggle = document.getElementById('theme-toggle');

  function systemPrefersDark() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  if (toggle) {
    toggle.addEventListener('click', function () {
      var current = root.getAttribute('data-theme');
      // "auto" until the reader expresses a preference; then it sticks.
      var isDark = current === 'dark' || (current !== 'light' && systemPrefersDark());
      var next = isDark ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('theme', next); } catch (e) {}
    });
  }

  // -------------------------------------------------------------------------
  // Search
  // -------------------------------------------------------------------------

  var dialog = document.getElementById('search-dialog');
  var input = document.getElementById('search-input');
  var results = document.getElementById('search-results');
  var empty = document.getElementById('search-empty');
  var openBtn = document.getElementById('search-open');

  if (!dialog || !input || !results || !dialog.showModal) return;

  var docs = null;
  var loading = null;

  // Zola's elasticlunr JSON: { documentStore: { docs: { ref: {id,title,body,...} } } }
  function load() {
    if (docs) return Promise.resolve(docs);
    if (loading) return loading;

    loading = fetch(window.HYPERTOR_SEARCH_INDEX)
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var store = (data.documentStore && data.documentStore.docs) || {};
        docs = Object.keys(store).map(function (ref) {
          var d = store[ref];
          return {
            url: d.id || ref,
            title: d.title || '',
            body: (d.body || '').replace(/\s+/g, ' '),
            path: d.path || ''
          };
        });
        return docs;
      })
      .catch(function () { docs = []; return docs; });

    return loading;
  }

  function score(doc, terms) {
    var title = doc.title.toLowerCase();
    var body = doc.body.toLowerCase();
    var total = 0;

    for (var i = 0; i < terms.length; i++) {
      var t = terms[i];
      // A term in the title is worth far more than one buried in prose: page
      // titles are what people are usually trying to get back to.
      if (title.indexOf(t) !== -1) total += 12;
      var at = body.indexOf(t);
      if (at !== -1) total += 3;
      else if (title.indexOf(t) === -1) return 0; // every term must appear
    }
    return total;
  }

  function snippet(doc, term) {
    var body = doc.body;
    var at = body.toLowerCase().indexOf(term);
    if (at === -1) return body.slice(0, 120) + '…';
    var start = Math.max(0, at - 45);
    return (start > 0 ? '…' : '') + body.slice(start, start + 140).trim() + '…';
  }

  function render(list, terms) {
    results.innerHTML = '';
    empty.hidden = list.length > 0;

    list.slice(0, 8).forEach(function (doc) {
      var li = document.createElement('li');
      var a = document.createElement('a');
      a.href = doc.url;

      var title = document.createElement('div');
      title.className = 'r-title';
      title.textContent = doc.title;

      var snip = document.createElement('div');
      snip.className = 'r-snip';
      snip.textContent = snippet(doc, terms[0]);

      a.appendChild(title);
      a.appendChild(snip);
      li.appendChild(a);
      results.appendChild(li);
    });
  }

  function search() {
    var q = input.value.trim().toLowerCase();
    if (q.length < 2) {
      results.innerHTML = '';
      empty.hidden = true;
      return;
    }

    var terms = q.split(/\s+/);
    load().then(function (all) {
      var scored = [];
      for (var i = 0; i < all.length; i++) {
        var s = score(all[i], terms);
        if (s > 0) scored.push({ doc: all[i], score: s });
      }
      scored.sort(function (a, b) { return b.score - a.score; });
      render(scored.map(function (x) { return x.doc; }), terms);
    });
  }

  input.addEventListener('input', search);

  function open() {
    if (!dialog.open) dialog.showModal();
    input.focus();
    input.select();
    load();
  }

  if (openBtn) openBtn.addEventListener('click', open);

  document.addEventListener('keydown', function (e) {
    var typingElsewhere = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);

    if ((e.key === 'k' && (e.metaKey || e.ctrlKey)) || (e.key === '/' && !typingElsewhere)) {
      e.preventDefault();
      open();
    }
  });

  // Arrow keys move through results without leaving the input.
  input.addEventListener('keydown', function (e) {
    if (e.key !== 'ArrowDown') return;
    var first = results.querySelector('a');
    if (first) { e.preventDefault(); first.focus(); }
  });
})();
