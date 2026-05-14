// ═══════════════════════════════════════════════════════════
//  IOBM e-Voting — main.js
//  Session countdown timer only.
//  Vote casting is handled in vote.html inline script.
// ═══════════════════════════════════════════════════════════

(function startSessionTimer() {
    const expiresEl = document.getElementById('session-expires');
    const timerEl   = document.getElementById('session-timer');

    if (!expiresEl || !timerEl) return;

    const expiresAt = new Date(expiresEl.dataset.expires + 'Z');

    function update() {
        const now  = new Date();
        const diff = Math.floor((expiresAt - now) / 1000);

        if (diff <= 0) {
            timerEl.textContent  = '⏱ 00:00';
            timerEl.style.color  = '#e74c3c';
            timerEl.style.fontWeight = '700';
            window.location.href = '/logout';
            return;
        }

        const mins = String(Math.floor(diff / 60)).padStart(2, '0');
        const secs = String(diff % 60).padStart(2, '0');
        timerEl.textContent = `⏱ ${mins}:${secs}`;

        if (diff < 60) {
            timerEl.style.color      = '#e74c3c';
            timerEl.style.fontWeight = '700';
        } else if (diff < 120) {
            timerEl.style.color      = '#e67e22';
            timerEl.style.fontWeight = '600';
        } else {
            timerEl.style.color      = '#ccc';
            timerEl.style.fontWeight = 'normal';
        }

        setTimeout(update, 1000);
    }

    update();
})();