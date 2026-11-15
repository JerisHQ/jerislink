#include "jl_opus.h"

OpusEncoder *jl_opus_encoder_create(int bitrate_bps, int inband_fec, int packet_loss_perc, int *err) {
    OpusEncoder *enc = opus_encoder_create(48000, 2, OPUS_APPLICATION_AUDIO, err);
    if (!enc) return NULL;
    int rc = opus_encoder_ctl(enc, OPUS_SET_BITRATE(bitrate_bps));
    if (rc == OPUS_OK) rc = opus_encoder_ctl(enc, OPUS_SET_COMPLEXITY(10));
    if (rc == OPUS_OK) rc = opus_encoder_ctl(enc, OPUS_SET_INBAND_FEC(inband_fec));
    if (rc == OPUS_OK) rc = opus_encoder_ctl(enc, OPUS_SET_PACKET_LOSS_PERC(packet_loss_perc));
    if (rc != OPUS_OK) {
        opus_encoder_destroy(enc);
        if (err) *err = rc;
        return NULL;
    }
    return enc;
}

int jl_opus_encoder_lookahead(OpusEncoder *enc) {
    opus_int32 v = 0;
    return opus_encoder_ctl(enc, OPUS_GET_LOOKAHEAD(&v)) == OPUS_OK ? (int)v : -1;
}
