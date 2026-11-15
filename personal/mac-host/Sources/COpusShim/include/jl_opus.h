#ifndef JL_OPUS_H
#define JL_OPUS_H
/* Non-variadic wrappers around opus_encoder_ctl / opus_decoder_ctl, which
 * Swift cannot call directly (C variadic functions are not imported). */
#include <opus.h>

/* 48 kHz stereo, OPUS_APPLICATION_AUDIO, constrained VBR (the default), in-band
 * FEC flag and expected packet loss as given. NULL on error (*err set). */
OpusEncoder *jl_opus_encoder_create(int bitrate_bps, int inband_fec, int packet_loss_perc, int *err);
/* Encoder lookahead in samples at 48 kHz (algorithmic delay beyond the frame). */
int jl_opus_encoder_lookahead(OpusEncoder *enc);
#endif
