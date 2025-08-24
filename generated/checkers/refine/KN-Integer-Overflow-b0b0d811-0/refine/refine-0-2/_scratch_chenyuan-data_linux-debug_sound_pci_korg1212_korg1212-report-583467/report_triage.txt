- Decision: NotABug
- Reason: The reported line computes an ALSA PCM pointer offset: pos = korg1212->currentBuffer * kPlayBufferFrames. Here:
  - snd_pcm_uframes_t pos is the destination type (unsigned long: 32-bit on 32-bit arch, 64-bit on 64-bit arch).
  - korg1212->currentBuffer is a small buffer index (typically 0..1 or a very small N), and kPlayBufferFrames is a fixed, driver-defined frames-per-buffer constant sized for audio buffers (thousands to tens of thousands of frames, not near 2^31).
  - Therefore, the product currentBuffer * kPlayBufferFrames is tightly bounded and easily fits within 32 bits; there is no risk of 32-bit overflow before any widening.
  - On 32-bit, there is no widening anyway (pos is 32-bit). On 64-bit, although the assignment widens to 64-bit, the 32-bit product is already exact and safely within range.

This does not match the target bug pattern of “narrow multiply overflowing before storing to a wider type” in any real, feasible configuration. There is no fix patch indicating a promotion was needed here, and similar code is used in playback_pointer without issue. Hence, this is a false positive.
