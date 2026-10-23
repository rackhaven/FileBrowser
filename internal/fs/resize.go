// Copyright (C) 2026 the Files authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package fs

import (
	"image"
	"image/color"
	"math"
)

// scaleToFit returns src resampled to fit inside a ThumbSize square with the
// aspect ratio kept. Only callers that already know the image is larger than
// the square use it, so both dimensions of the result are in range.
//
// A plain double loop with four taps per pixel is used instead of pulling in
// an external scaling library: the output is a 320-pixel list-row preview,
// not a print. Bilinear over premultiplied colours stays visually smooth at
// that size and costs tens of milliseconds per photo.
func scaleToFit(src image.Image) *image.RGBA {
	b := src.Bounds()
	// The longest edge becomes exactly ThumbSize; the other follows ratio.
	if b.Dx() >= b.Dy() {
		return bilinearResize(src, b, ThumbSize, maxInt(1, b.Dy()*ThumbSize/b.Dx()))
	}
	return bilinearResize(src, b, maxInt(1, b.Dx()*ThumbSize/b.Dy()), ThumbSize)
}

// bilinearResize copies src (its bounds sb), resampled to dstW x dstH, from
// the four source pixels around each destination sample centre. Taps outside
// the source bounds are clamped, so edge pixels never sample into nothing.
func bilinearResize(src image.Image, sb image.Rectangle, dstW, dstH int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, dstW, dstH))

	sxStep := float64(sb.Dx()) / float64(dstW)
	syStep := float64(sb.Dy()) / float64(dstH)

	for y := 0; y < dstH; y++ {
		fy := float64(sb.Min.Y) + (float64(y)+0.5)*syStep - 0.5
		y0, wy := splitWeight(fy)
		cy0 := clampInt(y0, sb.Min.Y, sb.Max.Y-1)
		cy1 := clampInt(y0+1, sb.Min.Y, sb.Max.Y-1)
		wy0, wy1 := 1-wy, wy

		for x := 0; x < dstW; x++ {
			fx := float64(sb.Min.X) + (float64(x)+0.5)*sxStep - 0.5
			x0, wx := splitWeight(fx)
			cx0 := clampInt(x0, sb.Min.X, sb.Max.X-1)
			cx1 := clampInt(x0+1, sb.Min.X, sb.Max.X-1)
			wx0, wx1 := 1-wx, wx

			r00, g00, b00, a00 := src.At(cx0, cy0).RGBA()
			r10, g10, b10, a10 := src.At(cx1, cy0).RGBA()
			r01, g01, b01, a01 := src.At(cx0, cy1).RGBA()
			r11, g11, b11, a11 := src.At(cx1, cy1).RGBA()

			// At().RGBA() reports premultiplied 16-bit values; blending
			// them linearly keeps semi-transparent pixels from bleeding
			// their fill colour into what should only change fractionally.
			dst.SetRGBA(x, y, color.RGBA{
				R: blend8(r00, r10, r01, r11, wx0, wx1, wy0, wy1),
				G: blend8(g00, g10, g01, g11, wx0, wx1, wy0, wy1),
				B: blend8(b00, b10, b01, b11, wx0, wx1, wy0, wy1),
				A: blend8(a00, a10, a01, a11, wx0, wx1, wy0, wy1),
			})
		}
	}
	return dst
}

// blend8 mixes the four taps of one premultiplied channel with the bilinear
// weights and rounds the 16-bit result to 8 bits.
func blend8(v00, v10, v01, v11 uint32, wx0, wx1, wy0, wy1 float64) uint8 {
	v := wx0*wy0*float64(v00) + wx1*wy0*float64(v10) +
		wx0*wy1*float64(v01) + wx1*wy1*float64(v11)
	return uint8(clampFloat(v/257+0.5, 0, 255))
}

// splitWeight splits a sample coordinate into an integer pixel index and the
// fraction towards the next pixel.
func splitWeight(f float64) (int, float64) {
	i := int(math.Floor(f))
	return i, f - float64(i)
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
