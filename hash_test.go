package main

import (
	"fmt"
	"testing"
)

// Hash128 computes the 128-bit MurmurHash3
func Hash128(key string, seed uint64) string {
	data := []byte(key)
	length := len(data)
	nblocks := length / 16

	h1 := uint64(seed)
	h2 := uint64(seed)

	c1 := uint64(0x87c37b91114253d5)
	c2 := uint64(0x4cf5ad432745937f)

	// Body
	for i := 0; i < nblocks; i++ {
		block := i * 16
		k1 := uint64(data[block+0]) | uint64(data[block+1])<<8 | uint64(data[block+2])<<16 | uint64(data[block+3])<<24 |
			uint64(data[block+4])<<32 | uint64(data[block+5])<<40 | uint64(data[block+6])<<48 | uint64(data[block+7])<<56

		k2 := uint64(data[block+8]) | uint64(data[block+9])<<8 | uint64(data[block+10])<<16 | uint64(data[block+11])<<24 |
			uint64(data[block+12])<<32 | uint64(data[block+13])<<40 | uint64(data[block+14])<<48 | uint64(data[block+15])<<56

		k1 *= c1
		k1 = (k1 << 31) | (k1 >> (64 - 31))
		k1 *= c2
		h1 ^= k1

		h1 = (h1 << 27) | (h1 >> (64 - 27))
		h1 += h2
		h1 = h1*5 + 0x52dce729

		k2 *= c2
		k2 = (k2 << 33) | (k2 >> (64 - 33))
		k2 *= c1
		h2 ^= k2

		h2 = (h2 << 31) | (h2 >> (64 - 31))
		h2 += h1
		h2 = h2*5 + 0x38495ab5
	}

	// Tail
	tail_index := nblocks * 16
	k1 := uint64(0)
	k2 := uint64(0)
	switch length & 15 {
	case 15:
		k2 ^= uint64(data[tail_index+14]) << 48
		fallthrough
	case 14:
		k2 ^= uint64(data[tail_index+13]) << 40
		fallthrough
	case 13:
		k2 ^= uint64(data[tail_index+12]) << 32
		fallthrough
	case 12:
		k2 ^= uint64(data[tail_index+11]) << 24
		fallthrough
	case 11:
		k2 ^= uint64(data[tail_index+10]) << 16
		fallthrough
	case 10:
		k2 ^= uint64(data[tail_index+9]) << 8
		fallthrough
	case 9:
		k2 ^= uint64(data[tail_index+8])
		k2 *= c2
		k2 = (k2 << 33) | (k2 >> (64 - 33))
		k2 *= c1
		h2 ^= k2
		fallthrough
	case 8:
		k1 ^= uint64(data[tail_index+7]) << 56
		fallthrough
	case 7:
		k1 ^= uint64(data[tail_index+6]) << 48
		fallthrough
	case 6:
		k1 ^= uint64(data[tail_index+5]) << 40
		fallthrough
	case 5:
		k1 ^= uint64(data[tail_index+4]) << 32
		fallthrough
	case 4:
		k1 ^= uint64(data[tail_index+3]) << 24
		fallthrough
	case 3:
		k1 ^= uint64(data[tail_index+2]) << 16
		fallthrough
	case 2:
		k1 ^= uint64(data[tail_index+1]) << 8
		fallthrough
	case 1:
		k1 ^= uint64(data[tail_index+0])
		k1 *= c1
		k1 = (k1 << 31) | (k1 >> (64 - 31))
		k1 *= c2
		h1 ^= k1
	}

	// Finalization
	h1 ^= uint64(length)
	h2 ^= uint64(length)

	h1 += h2
	h2 += h1

	h1 = fmix64(h1)
	h2 = fmix64(h2)

	h1 += h2
	h2 += h1

	return fmt.Sprintf("%016x%016x", h1, h2)
}

func fmix64(k uint64) uint64 {
	k ^= k >> 33
	k *= 0xff51afd7ed558ccd
	k ^= k >> 33
	k *= 0xc4ceb9fe1a85ec53
	k ^= k >> 33
	return k
}
func TestHelloHash(t *testing.T) {
	data := "ANGLE_instanced_arrays;EXT_blend_minmax;EXT_clip_control;EXT_color_buffer_half_float;EXT_depth_clamp;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_polygon_offset_clamp;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_texture_mirror_clamp_to_edge;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_blend_func_extended;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw;WEBGL_polygon_mode"

	hash := Hash128(data, 0)
	fmt.Println(hash)
}
