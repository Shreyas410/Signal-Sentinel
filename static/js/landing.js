function animateNumber(el, target, suffix) {
  if (!el || !isFinite(target)) return;
  const duration = 1200;
  const start = performance.now();
  function tick(now) {
    const progress = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    const value = Math.round(target * eased);
    el.textContent = value.toLocaleString() + (suffix || "");
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

async function loadStats() {
  try {
    const metaRes = await fetch("/api/threat-intel/meta");
    const meta = await metaRes.json();
    if (meta.total_seen) {
      animateNumber(document.getElementById("stat-cves"), meta.total_seen, "+");
    } else {
      document.getElementById("stat-cves").textContent = "1,700+";
    }
  } catch (e) {
    document.getElementById("stat-cves").textContent = "1,700+";
  }

  try {
    const metricsRes = await fetch("/api/metrics");
    if (metricsRes.ok) {
      const m = await metricsRes.json();
      animateNumber(document.getElementById("stat-precision"), Math.round(m.precision * 100), "%");
    } else {
      document.getElementById("stat-precision").textContent = "—";
    }
  } catch (e) {
    document.getElementById("stat-precision").textContent = "—";
  }
}

const FALLBACK_TICKER = [
  "CWE-89 SQL INJECTION", "CWE-798 HARDCODED CREDENTIALS", "CWE-918 SSRF",
  "CWE-502 INSECURE DESERIALIZATION", "CWE-79 CROSS-SITE SCRIPTING", "CWE-22 PATH TRAVERSAL",
  "CWE-287 IMPROPER AUTHENTICATION", "CWE-601 OPEN REDIRECT", "CWE-78 COMMAND INJECTION",
];

async function loadTicker() {
  const track = document.getElementById("ticker-track");
  let items = FALLBACK_TICKER;
  try {
    const res = await fetch("/api/threat-intel");
    const patterns = await res.json();
    const live = patterns
      .filter(p => p.status === "approved" || p.status === "pending")
      .map(p => (p.cwe ? p.cwe + " — " + p.name : p.name).toUpperCase());
    if (live.length) items = live;
  } catch (e) {
    // keep fallback
  }
  const row = items.map(t => `<span>${escapeHtml(t)}</span><span class="sep">//</span>`).join("");
  track.innerHTML = row + row; // duplicate for seamless loop
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function setupReveal() {
  const targets = document.querySelectorAll("[data-reveal]");
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add("in-view");
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.15 });
  targets.forEach(t => observer.observe(t));
}

function setupCursorGlow() {
  const glow = document.getElementById("cursor-glow");
  if (!glow) return;
  let raf = null;
  window.addEventListener("mousemove", e => {
    glow.classList.add("on");
    if (raf) return;
    raf = requestAnimationFrame(() => {
      glow.style.transform = `translate(${e.clientX}px, ${e.clientY}px)`;
      raf = null;
    });
  });
  window.addEventListener("mouseleave", () => glow.classList.remove("on"));
}

function setupHeroTilt() {
  const demo = document.getElementById("scan-demo");
  const hero = document.querySelector(".l-hero");
  if (!demo || !hero) return;
  hero.addEventListener("mousemove", e => {
    const rect = hero.getBoundingClientRect();
    const px = (e.clientX - rect.left) / rect.width - 0.5;
    const py = (e.clientY - rect.top) / rect.height - 0.5;
    demo.style.transform = `rotate(-1.4deg) rotateY(${px * 10}deg) rotateX(${-py * 8}deg)`;
  });
  hero.addEventListener("mouseleave", () => {
    demo.style.transform = "rotate(-1.4deg)";
  });
}

loadStats();
loadTicker();
setupReveal();
setupCursorGlow();
setupHeroTilt();
