import { HoverLabel } from './HoverLabel';

/**
 * Audio recorder - records audio via MediaRecorder API and feeds the
 * result into the attachment upload pipeline.
 *
 * Format strategy: MP4/AAC first (plays everywhere), OGG/Opus fallback
 * for desktop Firefox (which can't record MP4 but can play it). No
 * WebM - Safari can't play it. Two formats total, both widely playable.
 *
 * Renders: a toolbar button (idle/recording/uploading states) plus an
 * inline banner via the `onStateChange` callback so the parent can show
 * a prominent recording/uploading indicator in the editor body.
 *
 * States: idle → recording → uploading → idle.
 */

import { useState, useRef, useCallback, useEffect, type MutableRefObject } from 'react';
import { useTranslation } from 'react-i18next';
import { Microphone as MicIcon, CircleNotch } from './icons';
import type { EditorView } from '@tiptap/pm/view';
import { triggerAttachmentUpload } from './EncryptedAttachment';
import { formatDuration } from './formatDuration';

export type AudioRecordingState = 'idle' | 'recording' | 'uploading';

/** Hard cap on recording duration (seconds). Prevents storage bombs and browser memory issues. */
const MAX_RECORDING_SECONDS = 15 * 60; // 15 minutes
/** Seconds remaining when the UI shifts to warning colors. */
const WARNING_THRESHOLD = 60;

type Props = {
  editorView: EditorView | null;
  tabIndex?: number;
  /** Called when recording state changes so the parent can render an inline banner. */
  onStateChange?: (state: AudioRecordingState, duration: number) => void;
  /** Parent-owned ref that receives the stop function so the banner can trigger stop. */
  stopRef?: MutableRefObject<(() => void) | null>;
};

export function AudioRecorder({ editorView, tabIndex, onStateChange, stopRef }: Props) {
  const { t } = useTranslation('editor');
  const [state, setState] = useState<AudioRecordingState>('idle');
  const [duration, setDuration] = useState(0);
  const recorderRef = useRef<MediaRecorder | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const durationRef = useRef(0);

  const updateState = useCallback(
    (next: AudioRecordingState, dur: number) => {
      setState(next);
      onStateChange?.(next, dur);
    },
    [onStateChange],
  );

  const startRecording = useCallback(async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });

      // MP4/AAC: plays on every browser/OS. Records on Chrome 128+, Safari.
      // OGG/Opus: fallback for desktop Firefox (can't record MP4, but
      // every browser can play OGG except Safari - acceptable tradeoff
      // since Firefox share is tiny and Safari users record as MP4).
      // No WebM: Safari can't play it at all.
      const candidates = [
        'audio/mp4',                    // Chrome 128+, Safari 14.5+
        'audio/ogg;codecs=opus',        // Firefox
      ];
      const mimeType = candidates.find((m) => MediaRecorder.isTypeSupported(m));

      const recorder = new MediaRecorder(stream, mimeType ? { mimeType } : {});
      recorderRef.current = recorder;
      chunksRef.current = [];

      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) chunksRef.current.push(e.data);
      };

      recorder.onstop = () => {
        // Stop all tracks to release the microphone.
        stream.getTracks().forEach((t) => t.stop());

        if (timerRef.current) {
          clearInterval(timerRef.current);
          timerRef.current = null;
        }

        const finalDuration = durationRef.current;
        const actualMime = recorder.mimeType || 'audio/webm';
        const blob = new Blob(chunksRef.current, { type: actualMime });

        if (blob.size > 0 && editorView) {
          // Show uploading state while the attachment pipeline runs.
          updateState('uploading', finalDuration);

          const ext = actualMime.includes('mp4') ? 'm4a' : 'ogg';
          const timestamp = new Date()
            .toISOString()
            .replace(/[:.]/g, '-')
            .slice(0, 19);
          const filename = `recording-${timestamp}.${ext}`;
          const file = new File([blob], filename, { type: actualMime });
          triggerAttachmentUpload(file, editorView).finally(() => {
            updateState('idle', 0);
            setDuration(0);
          });
        } else {
          updateState('idle', 0);
          setDuration(0);
        }
      };

      recorder.start(1000); // 1s chunks for smoother stop
      durationRef.current = 0;
      setDuration(0);
      updateState('recording', 0);

      // Duration counter - auto-stops at MAX_RECORDING_SECONDS.
      // durationRef is the source of truth so no functional updater is
      // needed; notifying the parent (onStateChange -> Editor setState) from
      // inside a setDuration updater made React 19 warn "Cannot update
      // Editor2 while rendering AudioRecorder" - updaters run during render
      // and must stay pure. Side effects live in the interval callback.
      timerRef.current = setInterval(() => {
        const next = durationRef.current + 1;
        durationRef.current = next;
        setDuration(next);
        onStateChange?.('recording', next);
        if (next >= MAX_RECORDING_SECONDS) {
          // Hit the cap - stop on next tick, outside this callback.
          setTimeout(() => {
            if (recorderRef.current && recorderRef.current.state !== 'inactive') {
              recorderRef.current.stop();
            }
          }, 0);
        }
      }, 1000);
    } catch (err) {
      console.error('Microphone access denied:', err);
      updateState('idle', 0);
    }
  }, [editorView, updateState, onStateChange]);

  const stopRecording = useCallback(() => {
    if (recorderRef.current && recorderRef.current.state !== 'inactive') {
      recorderRef.current.stop();
    }
  }, []);

  // Expose stop function to parent via ref.
  useEffect(() => {
    if (stopRef) stopRef.current = state === 'recording' ? stopRecording : null;
  }, [stopRef, state, stopRecording]);

  // --- Toolbar button rendering ---

  if (state === 'uploading') {
    return (
      <HoverLabel label={t('audio.uploadingRecording')} position="below">
      <span
        className="inline-flex items-center gap-1.5 rounded px-2 py-1 text-accent"
        aria-label={t('audio.uploadingRecording')}
      >
        <CircleNotch className="animate-spin h-3.5 w-3.5" />
        <span className="text-xs font-medium">{t('audio.uploading')}</span>
      </span>
      </HoverLabel>
    );
  }

  if (state === 'recording') {
    return (
      <HoverLabel label={t('audio.stopRecording')} position="below">
      <button
        type="button"
        tabIndex={tabIndex}
        onMouseDown={(e) => e.preventDefault()}
        onClick={stopRecording}
        aria-label={t('audio.stopRecording')}
        className="inline-flex items-center gap-1.5 rounded px-2 py-1 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 transition"
      >
        {/* Pulsing red dot */}
        <span className="relative flex h-2.5 w-2.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-500 opacity-75" />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-600" />
        </span>
        <span className="text-xs font-medium tabular-nums">
          {formatDuration(duration)}
        </span>
      </button>
      </HoverLabel>
    );
  }

  return (
    <HoverLabel label={t('audio.recordAudio')} position="below-end">
    <button
      type="button"
      tabIndex={tabIndex}
      onMouseDown={(e) => e.preventDefault()}
      onClick={startRecording}
      aria-label={t('audio.recordAudio')}
      className="flex items-center justify-center w-9 h-9 rounded-lg text-neutral-600 dark:text-neutral-300 [@media(hover:hover)]:hover:bg-neutral-200 [@media(hover:hover)]:dark:hover:bg-neutral-800 active:scale-95 transition outline-none shrink-0"
    >
      <MicIcon size={19} />
    </button>
    </HoverLabel>
  );
}

// ------------------------------------------------------------------
// Inline banner - rendered by the parent (Editor) between toolbar
// and EditorContent for prominent in-editor feedback.
// ------------------------------------------------------------------

export function AudioRecordingBanner({
  state,
  duration,
  onStop,
}: {
  state: AudioRecordingState;
  duration: number;
  onStop: () => void;
}) {
  const { t } = useTranslation('editor');
  if (state === 'idle') return null;

  if (state === 'uploading') {
    return (
      <div className="flex items-center gap-2 px-3 py-2 bg-accent/10 dark:bg-accent/15 border-b border-accent/20 text-sm text-accent">
        <CircleNotch className="animate-spin h-4 w-4 shrink-0" />
        <span className="font-medium">{t('audio.savingRecording')}</span>
        <span className="text-xs opacity-70">{formatDuration(duration)}</span>
      </div>
    );
  }

  // Recording state
  const remaining = MAX_RECORDING_SECONDS - duration;
  const warn = remaining <= WARNING_THRESHOLD;
  const pct = Math.min((duration / MAX_RECORDING_SECONDS) * 100, 100);

  return (
    <div className={`relative border-b text-sm ${
      warn
        ? 'bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-900/50'
        : 'bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-900/50'
    }`}>
      {/* Progress bar */}
      <div
        className={`absolute inset-0 opacity-15 transition-colors ${warn ? 'bg-amber-500' : 'bg-red-500'}`}
        style={{ width: `${pct}%` }}
      />
      <div className="relative flex items-center gap-2 px-3 py-2">
        <span className="relative flex h-3 w-3 shrink-0">
          <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${warn ? 'bg-amber-500' : 'bg-red-500'}`} />
          <span className={`relative inline-flex rounded-full h-3 w-3 ${warn ? 'bg-amber-600' : 'bg-red-600'}`} />
        </span>
        <span className={`font-medium ${warn ? 'text-amber-700 dark:text-amber-400' : 'text-red-700 dark:text-red-400'}`}>
          {t('audio.recording')}
        </span>
        <span className={`tabular-nums font-medium ${warn ? 'text-amber-600 dark:text-amber-400' : 'text-red-600 dark:text-red-400'}`}>
          {formatDuration(duration)} / {formatDuration(MAX_RECORDING_SECONDS)}
        </span>
        {warn && (
          <span className="text-xs text-amber-600 dark:text-amber-400">
            {t('audio.secondsLeft', { count: remaining })}
          </span>
        )}
        <button
          type="button"
          onClick={onStop}
          className={`ml-auto rounded px-2.5 py-0.5 text-xs font-medium text-white transition ${
            warn ? 'bg-amber-600 hover:bg-amber-700' : 'bg-red-600 hover:bg-red-700'
          }`}
        >
          {t('audio.stop')}
        </button>
      </div>
    </div>
  );
}

