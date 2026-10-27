'use strict';
(() => {
  // This is a presentation preference only. Authentication remains in HttpOnly
  // cookies; the edition controller never reads credentials or calls the API.
  const KEY = 'sentinelx.edition';
  const editions = new Set(['gold', 'street']);
  const root = document.documentElement;
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  const finePointer = window.matchMedia('(pointer: fine)');
  let active = false;
  let observer = null;
  let sceneFrame = null;
  let pointerFrame = null;
  let cursor = null;
  let lastPoint = null;
  let previousScene = null;
  let sceneSequence = 0;
  let returnFocus = null;
  let pointerListening = false;

  function storedEdition() {
    try {
      const value = localStorage.getItem(KEY);
      return editions.has(value) ? value : null;
    } catch {
      // Storage may be disabled. Switching remains available for this page.
      return null;
    }
  }

  function applyEdition(value, persist = false) {
    if (!editions.has(value)) return;
    const changed = root.dataset.edition !== value;
    root.dataset.edition = value;
    document.querySelectorAll('[data-edition-choice]').forEach(button => {
      button.setAttribute('aria-pressed', String(button.dataset.editionChoice === value));
    });
    if (persist) {
      try { localStorage.setItem(KEY, value); } catch { /* Nonessential preference. */ }
    }
    if (changed) {
      document.dispatchEvent(new CustomEvent('sentinelx:edition-changed', {detail: {edition: value}}));
    }
  }

  // Deferred before the application scripts: establish the saved palette before
  // authentication restoration starts, without awaiting or interrupting it.
  applyEdition(storedEdition() || 'gold');

  function chooser() { return document.getElementById('edition-dialog'); }

  function openChooser() {
    const dialog = chooser();
    if (!dialog || dialog.open) return;
    returnFocus = document.activeElement;
    dialog.showModal();
  }

  function closeChooser() {
    const dialog = chooser();
    if (!dialog?.open) return;
    dialog.close();
    // Native dialogs restore focus themselves where possible. An explicit
    // opener is preserved when the visitor reopens the chooser from a switch.
    if (returnFocus instanceof HTMLElement && returnFocus.isConnected && returnFocus !== document.body) {
      returnFocus.focus({preventScroll: true});
    }
    returnFocus = null;
  }

  function choose(value) {
    if (!editions.has(value)) return;
    applyEdition(value, true);
    closeChooser();
  }

  function click(event) {
    if (!(event.target instanceof Element)) return;
    const choice = event.target.closest('[data-edition-choice]');
    if (choice) {
      choose(choice.dataset.editionChoice);
      return;
    }
    if (event.target.closest('[data-edition-skip]')) {
      choose('gold');
      return;
    }
    if (event.target.closest('[data-open-editions]')) openChooser();
  }

  function cancelChooser(event) {
    // Escape always dismisses the chooser; it is not an onboarding dead end.
    event.preventDefault();
    choose('gold');
  }

  function scene() {
    const admin = document.getElementById('adm-shell');
    if (admin && !admin.hidden) {
      const selected = document.querySelector('[data-admin-view][aria-current="page"], [data-admin-view].active');
      return {key: 'admin:' + (selected?.dataset.adminView || 'overview'), container: document.getElementById('adm-main')};
    }
    const workspace = document.getElementById('app-shell');
    if (workspace && !workspace.hidden) {
      const selected = document.querySelector('[data-view][aria-current="page"], [data-view].active');
      return {key: 'workspace:' + (selected?.dataset.view || 'overview'), container: document.getElementById('main-content')};
    }
    return {
      key: admin ? 'admin:auth' : 'workspace:auth',
      container: document.getElementById(admin ? 'adm-auth-section' : 'auth-section')
    };
  }

  function syncScene() {
    sceneFrame = null;
    if (!active) return;
    const current = scene();
    if (!current.container || current.key === previousScene) return;
    previousScene = current.key;
    root.dataset.scene = current.key;
    root.dataset.sceneSequence = String(++sceneSequence);
    if (reduced.matches) return;
    // Add entrance markers only when navigation/authentication changes scene.
    // Polling and search replace the same view's nodes without these markers,
    // so fresh data does not repeatedly animate or move the reader's content.
    Array.from(current.container.children).slice(0, 8).forEach((element, index) => {
      element.dataset.reveal = String(sceneSequence);
      element.style.setProperty('--reveal-order', String(index));
    });
  }

  function scheduleScene() {
    if (active && sceneFrame === null) sceneFrame = requestAnimationFrame(syncScene);
  }

  function hideCursor() {
    if (pointerFrame !== null) cancelAnimationFrame(pointerFrame);
    pointerFrame = null;
    if (cursor) cursor.hidden = true;
  }

  function movePointer(event) {
    if (event.pointerType !== 'mouse' || document.hidden) return;
    lastPoint = {x: event.clientX, y: event.clientY};
    if (pointerFrame !== null) return;
    pointerFrame = requestAnimationFrame(() => {
      pointerFrame = null;
      if (!cursor || !lastPoint || !active) return;
      cursor.hidden = false;
      cursor.style.transform = `translate3d(${lastPoint.x}px, ${lastPoint.y}px, 0)`;
    });
  }

  function updatePointer() {
    const enabled = active && finePointer.matches && !reduced.matches;
    if (enabled && !pointerListening) {
      cursor = document.createElement('div');
      cursor.id = 'edition-cursor';
      cursor.className = 'edition-cursor';
      cursor.setAttribute('aria-hidden', 'true');
      cursor.style.pointerEvents = 'none';
      cursor.hidden = true;
      document.body.append(cursor);
      document.addEventListener('pointermove', movePointer, {passive: true});
      document.addEventListener('pointerleave', hideCursor);
      pointerListening = true;
    } else if (!enabled && pointerListening) {
      document.removeEventListener('pointermove', movePointer);
      document.removeEventListener('pointerleave', hideCursor);
      hideCursor();
      cursor?.remove();
      cursor = null;
      pointerListening = false;
    }
  }

  function motionChanged() {
    root.dataset.motion = reduced.matches ? 'reduced' : 'full';
    if (reduced.matches) {
      document.querySelectorAll('[data-reveal]').forEach(element => {
        element.removeAttribute('data-reveal');
        element.style.removeProperty('--reveal-order');
      });
    }
    updatePointer();
  }

  function visibilityChanged() { if (document.hidden) hideCursor(); }

  function storageChanged(event) {
    if (event.key === KEY && editions.has(event.newValue)) applyEdition(event.newValue);
  }

  function activate() {
    if (active) return;
    active = true;
    applyEdition(storedEdition() || root.dataset.edition || 'gold');
    document.addEventListener('click', click);
    document.addEventListener('sentinelx:view-rendered', scheduleScene);
    document.addEventListener('visibilitychange', visibilityChanged);
    chooser()?.addEventListener('cancel', cancelChooser);
    window.addEventListener('storage', storageChanged);
    reduced.addEventListener('change', motionChanged);
    finePointer.addEventListener('change', updatePointer);
    motionChanged();
    observer = new MutationObserver(scheduleScene);
    observer.observe(document.body, {childList: true, subtree: true, attributes: true, attributeFilter: ['hidden', 'aria-current', 'class']});
    scheduleScene();
  }

  function deactivate() {
    active = false;
    observer?.disconnect();
    observer = null;
    if (sceneFrame !== null) cancelAnimationFrame(sceneFrame);
    sceneFrame = null;
    document.removeEventListener('click', click);
    document.removeEventListener('sentinelx:view-rendered', scheduleScene);
    document.removeEventListener('visibilitychange', visibilityChanged);
    chooser()?.removeEventListener('cancel', cancelChooser);
    window.removeEventListener('storage', storageChanged);
    reduced.removeEventListener('change', motionChanged);
    finePointer.removeEventListener('change', updatePointer);
    updatePointer();
  }

  function boot() {
    activate();
    if (!storedEdition()) openChooser();
  }

  window.addEventListener('pagehide', deactivate);
  window.addEventListener('pageshow', event => { if (event.persisted) activate(); });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, {once: true});
  else boot();
})();
