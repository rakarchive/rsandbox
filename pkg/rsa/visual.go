package rsa

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"image"
	"image/color"
	"math"
	"math/rand/v2"

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

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	var buf bytes.Buffer

	// Write width and height (big endian)
	if err := binary.Write(&buf, binary.BigEndian, uint16(height)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(width)); err != nil {
		return nil, err
	}

	// Encode pixels as 2-bit: 00 = white, 01 = black
	var byteBuf byte
	bitPos := 6

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := color.GrayModel.Convert(img.At(x, y)).(color.Gray)
			var val byte
			if c.Y > 128 {
				val = byte(White)
			} else {
				val = byte(Black)
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
		rand := Pixel(1 << (rand.Int() & 1))
		if pixel == Blocker {
			share1.Pixels = append(share1.Pixels, rand)
			share2.Pixels = append(share2.Pixels, rand.Other())
		} else {
			share1.Pixels = append(share1.Pixels, rand)
			share2.Pixels = append(share2.Pixels, rand)
		}
	}

	return &share1, &share2
}

type Pixel byte

const (
	Blocker Pixel = 0b00
	Transpr Pixel = 0b11
	Left    Pixel = 0b10
	Right   Pixel = 0b01

	White Pixel = Transpr
	Black Pixel = White ^ 0b11
)

func (p Pixel) Other() Pixel {
	return p ^ 0b11
}

func (p Pixel) Add(q Pixel) Pixel {
	return p & q
}

func (p Pixel) String() string {
	return []string{
		Blocker:        "██",
		Blocker ^ 0b11: "  ",
		Left:           "█ ",
		Right:          " █",
	}[p]
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
	image.Rows = int(binary.BigEndian.Uint16(data[0:2]))
	image.Cols = int(binary.BigEndian.Uint16(data[2:4]))
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
			str += image.Pixels[i*image.Cols+j].String()
		}
		str += "\n"
	}

	return str
}

func (image *Image) Add(rhs *Image, result *Image) *Image {
	size := image.Rows * image.Cols
	result.Rows = image.Rows
	result.Cols = image.Cols
	result.Pixels = result.Pixels[:size]
	for i := 0; i < len(result.Pixels); i++ {
		result.Pixels[i] = image.Pixels[i] & rhs.Pixels[i]
	}

	return result
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

func (image *Image) GetRows(y1, y2 int) *Image {
	return &Image{Rows: y2 - y1, Cols: image.Cols, Pixels: image.Pixels[y1*image.Cols : y2*image.Cols]}
}
