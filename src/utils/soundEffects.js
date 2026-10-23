/**
 * Optional lightweight Web Audio synthesizer for tactical UI sound cues.
 * Disabled by default per user specification; never autoplays intrusive audio.
 */
class SoundManager {
  constructor() {
    this.enabled = false;
    this.ctx = null;
  }

  setEnabled(enabled) {
    this.enabled = Boolean(enabled);
  }

  _getContext() {
    if (!this.enabled || typeof window === 'undefined') return null;
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return null;
    if (!this.ctx) {
      this.ctx = new AudioCtx();
    }
    return this.ctx;
  }

  playTone(freq = 520, durationMs = 90, type = 'sine', gainLevel = 0.04) {
    try {
      const ctx = this._getContext();
      if (!ctx) return;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      gain.gain.setValueAtTime(gainLevel, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + durationMs / 1000);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + durationMs / 1000);
    } catch {
      // Ignore audio errors in restricted environments
    }
  }

  playEvidenceAdded() {
    this.playTone(660, 80, 'triangle', 0.04);
  }

  playAlertTriggered() {
    this.playTone(440, 120, 'sawtooth', 0.03);
  }

  playResponseAction() {
    this.playTone(580, 110, 'sine', 0.04);
  }

  playMissionCompleted() {
    this.playTone(523.25, 100, 'triangle', 0.04);
    setTimeout(() => this.playTone(659.25, 140, 'triangle', 0.04), 110);
  }
}

export const soundManager = new SoundManager();
