## Patch Description

check whether referenced PPS exists (fixes #393)

The code was accessing a PPS object field (pps_read) without first checking 
if the PPS object itself is null. This can lead to a null pointer dereference 
vulnerability that causes crashes or undefined behavior.

The fix adds a null check before accessing the object's fields and properly 
handles the error case with appropriate warning and return false.

Fixes: CVE-XXXX (potential null pointer dereference)
Source: https://github.com/strukturag/libde265/commit/0b1752abff97cb542941d317a0d18aa50cb199b1

## Buggy Code

```cpp
// libde265/decctx.cc
// returns whether we can continue decoding the stream or whether we should give up
bool decoder_context::process_slice_segment_header(slice_segment_header* hdr,
                                                   de265_error* err, de265_PTS pts,
                                                   nal_header* nal_hdr,
                                                   void* user_data)
{
  *err = DE265_OK;

  flush_reorder_buffer_at_this_frame = false;


  // get PPS and SPS for this slice

  int pps_id = hdr->slice_pic_parameter_set_id;
  if (pps[pps_id]->pps_read==false) {
    logerror(LogHeaders, "PPS %d has not been read\n", pps_id);
    assert(false); // TODO

  }

  current_pps = pps[pps_id];
  current_sps = sps[ (int)current_pps->seq_parameter_set_id ];
  current_vps = vps[ (int)current_sps->video_parameter_set_id ];

  calc_tid_and_framerate_ratio();


  // --- prepare decoding of new picture ---

  if (hdr->first_slice_segment_in_pic_flag) {

    // previous picture has been completely decoded

    //ctx->push_current_picture_to_output_queue();

    current_image_poc_lsb = hdr->slice_pic_order_cnt_lsb;


    seq_parameter_set* sps = current_sps.get();


    // --- find and allocate image buffer for decoding ---

    int image_buffer_idx;
    bool isOutputImage = (!sps->sample_adaptive_offset_enabled_flag || param_disable_sao);
    image_buffer_idx = dpb.new_image(current_sps, this, pts, user_data, isOutputImage);
    if (image_buffer_idx < 0) {
      *err = (de265_error)(-image_buffer_idx);
      return false;
    }

    /*de265_image* */ img = dpb.get_image(image_buffer_idx);
    img->nal_hdr = *nal_hdr;

    // Note: sps is already set in new_image() -> ??? still the case with shared_ptr ?

    img->set_headers(current_vps, current_sps, current_pps);

    img->decctx = this;

    img->clear_metadata();


    if (isIRAP(nal_unit_type)) {
      if (isIDR(nal_unit_type) ||
          isBLA(nal_unit_type) ||
          first_decoded_picture ||
          FirstAfterEndOfSequenceNAL)
        {
          NoRaslOutputFlag = true;
          FirstAfterEndOfSequenceNAL = false;
        }
      else if (0) // TODO: set HandleCraAsBlaFlag by external means
        {
        }
      else
        {
          NoRaslOutputFlag   = false;
          HandleCraAsBlaFlag = false;
        }
    }


    if (isRASL(nal_unit_type) &&
        NoRaslOutputFlag)
      {
        img->PicOutputFlag = false;
      }
    else
      {
        img->PicOutputFlag = !!hdr->pic_output_flag;
      }

    process_picture_order_count(hdr);

    if (hdr->first_slice_segment_in_pic_flag) {
      // mark picture so that it is not overwritten by unavailable reference frames
      img->PicState = UsedForShortTermReference;

      *err = process_reference_picture_set(hdr);
      if (*err != DE265_OK) {
        return false;
      }
    }

    img->PicState = UsedForShortTermReference;

    log_set_current_POC(img->PicOrderCntVal);


    // next image is not the first anymore

    first_decoded_picture = false;
  }
  else {
    // claims to be not the first slice, but there is no active image available

    if (img == NULL) {
      return false;
    }
  }

  if (hdr->slice_type == SLICE_TYPE_B ||
      hdr->slice_type == SLICE_TYPE_P)
    {
      bool success = construct_reference_picture_lists(hdr);
      if (!success) {
        return false;
      }
    }

  //printf("process slice segment header\n");

  loginfo(LogHeaders,"end of process-slice-header\n");
  dpb.log_dpb_content();


  if (hdr->dependent_slice_segment_flag==0) {
    hdr->SliceAddrRS = hdr->slice_segment_address;
  } else {
    hdr->SliceAddrRS = previous_slice_header->SliceAddrRS;
  }

  previous_slice_header = hdr;


  loginfo(LogHeaders,"SliceAddrRS = %d\n",hdr->SliceAddrRS);

  return true;
}
```


## Bug Fix Patch

```diff
diff --git a/libde265/decctx.cc b/libde265/decctx.cc
index abc123..def456 100644
--- a/libde265/decctx.cc
+++ b/libde265/decctx.cc
@@ -2004,9 +2004,10 @@ bool decoder_context::process_slice_segment_header(slice_segment_header* hdr,
   // get PPS and SPS for this slice

  int pps_id = hdr->slice_pic_parameter_set_id;
-  if (pps[pps_id]->pps_read==false) {
+  if (pps[pps_id] == nullptr || pps[pps_id]->pps_read == false) {
     logerror(LogHeaders, "PPS %d has not been read\n", pps_id);
- assert(false); // TODO
+     img->decctx->add_warning(DE265_WARNING_NONEXISTING_PPS_REFERENCED, false);
+     return false;
  }

  current_pps = pps[pps_id];
```