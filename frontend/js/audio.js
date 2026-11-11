// Small synthesized UI sounds (Web Audio, no files). Off when muted.

const KEY = "nta.muted";
let ctx = null;
let muted = false;
let lastAlarm = 0;

try {
  muted = localStorage.getItem(KEY) === "1";
} catch {
  /* storage blocked */
}

function ac() {
  if (!ctx) {
    const C = window.AudioContext || window.webkitAudioContext;
    if (!C) return null;
    ctx = new C();
  }
  if (ctx.state === "suspended") ctx.resume();
  return ctx;
}

function tone({
  type = "sine",
  from,
  to = from,
  dur = 0.2,
  gain = 0.05,
  delay = 0,
}) {
  const a = ac();
  if (!a) return;
  const t0 = a.currentTime + delay;
  const osc = a.createOscillator();
  const g = a.createGain();
  const filter = a.createBiquadFilter();
  filter.type = "lowpass";
  filter.frequency.value = 2400;
  osc.type = type;
  osc.frequency.setValueAtTime(from, t0);
  osc.frequency.exponentialRampToValueAtTime(Math.max(1, to), t0 + dur);
  g.gain.setValueAtTime(0.0001, t0);
  g.gain.exponentialRampToValueAtTime(gain, t0 + 0.015);
  g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
  osc.connect(filter).connect(g).connect(a.destination);
  osc.start(t0);
  osc.stop(t0 + dur + 0.02);
}

export const sound = {
  get muted() {
    return muted;
  },
  setMuted(v) {
    muted = v;
    try {
      localStorage.setItem(KEY, v ? "1" : "0");
    } catch {
      /* ignore */
    }
  },
  /** Rising sweep when capture starts. */
  start() {
    if (muted) return;
    tone({ type: "sawtooth", from: 180, to: 880, dur: 0.35, gain: 0.03 });
    tone({
      type: "sine",
      from: 880,
      to: 1320,
      dur: 0.12,
      gain: 0.03,
      delay: 0.32,
    });
  },
  /** Two-tone alarm for high/critical alerts, at most every 4 s. */
  alarm() {
    if (muted) return;
    const now = performance.now();
    if (now - lastAlarm < 4000) return;
    lastAlarm = now;
    tone({ type: "square", from: 740, dur: 0.11, gain: 0.025 });
    tone({ type: "square", from: 520, dur: 0.16, gain: 0.025, delay: 0.13 });
    tone({ type: "square", from: 740, dur: 0.11, gain: 0.02, delay: 0.32 });
  },
  /** Soft tick when a new location lands on the map. */
  tick() {
    if (muted) return;
    tone({ type: "sine", from: 1800, to: 1200, dur: 0.05, gain: 0.012 });
  },
  /** Prime the audio context on the first user gesture. */
  unlock() {
    if (!muted) ac();
  },
};
