package rsa

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/png"
	"math"
	"math/rand"
	"os"

	"golang.org/x/image/draw"
)

// ConvertImageToBWBinary takes a PNG image and converts it to a custom B/W binary format
// Optionally resizes to given width (keeping aspect ratio)
func ConvertImageToBWBinary(img image.Image, resizeWidth int) (*Image, error) {
	// Resize if requested
	if resizeWidth > 0 {
		origBounds := img.Bounds()
		origWidth := origBounds.Dx()
		origHeight := origBounds.Dy()
		scale := float64(resizeWidth) / float64(origWidth)
		newHeight := int(math.Round(float64(origHeight) * scale))

		resized := image.NewRGBA(image.Rect(0, 0, resizeWidth, newHeight))
		draw.NearestNeighbor.Scale(resized, resized.Bounds(), img, origBounds, draw.Over, nil)
		img = resized
	}

	file, err := os.Create("resize.png")
	if err != nil {
		return nil, err
	}

	err = png.Encode(file, img)
	if err != nil {
		return nil, err
	}

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	var buf bytes.Buffer

	// Write width and height (big endian)
	if err := binary.Write(&buf, binary.BigEndian, uint16(width)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(height)); err != nil {
		return nil, err
	}

	// Encode pixels as 2-bit: 00 = white, 01 = black
	var byteBuf byte
	bitPos := 6

	for x := bounds.Min.X; x < bounds.Max.X; x++ {
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			c := color.GrayModel.Convert(img.At(x, y)).(color.Gray)
			var val byte
			if c.Y > 128 {
				val = 0b00 // white
			} else {
				val = 0b01 // black
			}
			byteBuf |= val << bitPos
			bitPos -= 2
			if bitPos < 0 {
				buf.WriteByte(byteBuf)
				byteBuf = 0
				bitPos = 6
			}
		}
	}

	if bitPos != 6 {
		buf.WriteByte(byteBuf) // flush last byte
	}

	return NewImageRaw(buf.Bytes())
}

func CreateShares(secret *Image) (*Image, *Image) {
	share1 := Image{Rows: secret.Rows, Cols: secret.Cols, Pixels: []Pixel{}}
	share2 := Image{Rows: secret.Rows, Cols: secret.Cols, Pixels: []Pixel{}}

	for _, pixel := range secret.Pixels {
		rand := Pixel(rand.Int() & 1)
		if pixel == Blocker {
			share1.Pixels = append(share1.Pixels, Left^rand)
			share2.Pixels = append(share2.Pixels, Right^rand)
		} else {
			share1.Pixels = append(share1.Pixels, Left^rand)
			share2.Pixels = append(share2.Pixels, Left^rand)
		}
	}

	return &share1, &share2
}

type Pixel byte

const (
	White Pixel = iota
	Black
	Left
	Right

	Blocker = Black
)

func (p Pixel) Other() Pixel {
	return p ^ 1
}

func (p Pixel) Add(q Pixel) Pixel {
	if p == Blocker || q == Blocker.Other() {
		return p
	} else if p == Blocker.Other() || q == Blocker {
		return q
	} else if p == q {
		return p
	} else {
		return Blocker
	}
}

func (p Pixel) String() string {
	switch p {
	case White:
		return "██"
	case Black:
		return "  "
	case Left:
		return "█ "
	case Right:
		return " █"
	}

	panic("unreachable")
}

func NewImage(repr string) (*Image, error) {
	data, err := base64.StdEncoding.DecodeString(repr)
	if err != nil {
		return nil, err
	}

	return NewImageRaw(data)
}

func NewImageRaw(data []byte) (*Image, error) {
	var image Image
	image.Cols = int(binary.BigEndian.Uint16(data[0:2]))
	image.Rows = int(binary.BigEndian.Uint16(data[2:4]))
	image.Pixels = make([]Pixel, 0, image.Rows*image.Cols)

	data = data[4:]
outer:
	for _, b := range data {
		for j := 6; j >= 0; j -= 2 {
			image.Pixels = append(image.Pixels, Pixel((b>>j)&3))

			if len(image.Pixels) == image.Rows*image.Cols {
				break outer
			}
		}
	}

	return &image, nil
}

type Image struct {
	Rows, Cols int
	Pixels     []Pixel
}

func (image *Image) String() string {
	str := ""
	for i := 0; i < image.Rows; i++ {
		for j := 0; j < image.Cols; j++ {
			str += image.Pixels[j*image.Rows+i].String()
		}
		str += "\n"
	}

	return str
}

func (image *Image) Add(rhs *Image) (*Image, error) {
	if image.Rows != rhs.Rows || image.Cols != rhs.Cols {
		return nil, errors.New("different size images getting added")
	}

	result := Image{Rows: image.Rows, Cols: image.Cols, Pixels: []Pixel{}}
	for i, pixel := range image.Pixels {
		result.Pixels = append(result.Pixels, pixel.Add(rhs.Pixels[i]))
	}

	return &result, nil
}

func (image *Image) Base64() string {
	raw := []byte{byte(image.Cols), byte(image.Rows)}

	b := byte(0)
	for i, pixel := range image.Pixels {
		b <<= 2
		b |= byte(pixel)

		if i%4 == 3 {
			raw = append(raw, b)
			b = 0
		}
	}

	return base64.RawStdEncoding.EncodeToString(raw)
}
