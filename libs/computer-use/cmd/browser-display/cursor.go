// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"image"
	"image/png"
	"strings"
	"sync/atomic"

	"github.com/robotn/xgb"
	"github.com/robotn/xgb/xfixes"
)

// A viewer that draws the pointer itself needs the cursor the browser chose,
// as a CSS keyword the viewer's own platform can draw. Chrome on this image
// names none of its cursors: without an Xcursor theme it builds each one from
// the X server's cursor font. The image identifies the cursor instead, and
// cursorClasses maps those images to keywords. Any other image, such as a
// page's url() cursor, travels once as a small PNG.
const maximumCursorPNG = 4096
const maximumCursorSide = 256

// cursorClass names one cursor image: the keyword the helper answers for it,
// and the keywords the image stands for, as measured. Several keywords share
// one image when Chrome finds no distinct cursor for them, so the display
// alone cannot tell them apart; the driver names the member the hovered
// element's computed cursor asks for, and css stands when it cannot. members
// is shared by every identity of the class and never written.
type cursorClass struct {
	css     string
	members []string
}

// standsFor is the class of an image Chrome draws for the given keywords,
// answered as the first of them.
func standsFor(keywords ...string) cursorClass {
	return cursorClass{css: keywords[0], members: keywords}
}

// identity is the class as the report of one displayed cursor object.
func (c cursorClass) identity(serial uint32) cursorIdentity {
	return cursorIdentity{Serial: serial, CSS: &c.css, Members: c.members}
}

// arrow is the plain pointer's class, and what stands for a cursor the helper
// cannot describe.
var arrow = standsFor("default")

// xCursor is the server's own cursor, shown when Chrome sets none: it stands
// for the eleven keywords Chrome draws no cursor for, and is answered as
// default, which stands when the driver can name none of them.
var xCursor = cursorClass{css: "default", members: []string{"context-menu", "help", "vertical-text", "alias", "copy", "no-drop", "not-allowed", "nesw-resize", "nwse-resize", "zoom-in", "zoom-out"}}

// cursorClasses maps each cursor image the pinned Chrome shows for a CSS
// cursor keyword to its class. It is measured, not derived: image
// qualification (integration_test.py, cursor section) hovers a page with every
// keyword through native input and requires exactly these answers and
// members, so a new Chrome or cursor font that draws differently fails
// qualification instead of mislabelling the pointer. auto computes to
// default, so the arrow stands for default alone.
//
// Measured with Chrome for Testing 152.0.7977.82 on Xvfb 21.1 at DPR 2.
var cursorClasses = map[string]cursorClass{
	"94158445512d4df1": arrow,                                // left_ptr
	"341ed0635eb5f0b7": xCursor,                              // X_cursor: Chrome set no cursor
	"2443085e6d56c5a3": standsFor("none"),                    // 1x1 transparent
	"161e664684b459d3": standsFor("pointer", "grabbing"),     // hand2
	"06efea585b55fe7a": standsFor("progress", "wait"),        // watch
	"24ef70fd9a6ae9c1": standsFor("cell"),                    // plus
	"654fecff6f5df623": standsFor("crosshair"),               // crosshair
	"497c3dc712a52690": standsFor("text"),                    // xterm
	"f9ef0371514cf529": standsFor("move", "all-scroll"),      // fleur
	"fe7fc6668a1bbdad": standsFor("grab"),                    // hand1
	"59ed0f8aa964b39f": standsFor("ew-resize", "col-resize"), // sb_h_double_arrow
	"20a5227b8715d419": standsFor("ns-resize", "row-resize"), // sb_v_double_arrow
	"db08dd7c54998e65": standsFor("n-resize"),                // top_side
	"9f5126b351c2a866": standsFor("e-resize"),                // right_side
	"e8b754deb1f5c814": standsFor("s-resize"),                // bottom_side
	"3e99daf1bb883067": standsFor("w-resize"),                // left_side
	"b05715ab382439d7": standsFor("ne-resize"),               // top_right_corner
	"a3b6365a43f5b11c": standsFor("nw-resize"),               // top_left_corner
	"34eb599d9ee27030": standsFor("se-resize"),               // bottom_right_corner
	"b07fcc769e43c0fb": standsFor("sw-resize"),               // bottom_left_corner
}

// cursorImage is a cursor the table does not name, in device pixels at the
// display's scale.
type cursorImage struct {
	Hash   string `json:"hash"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	HotX   int    `json:"hotX"`
	HotY   int    `json:"hotY"`
	Scale  int    `json:"scale"`
	PNG    []byte `json:"png"`
}

// cursorIdentity is what a capture reply carries when the displayed cursor
// differs from the one last reported. Exactly one of CSS and Image is set. A
// keyword's Members are the keywords its image stands for; an image has none.
type cursorIdentity struct {
	Serial  uint32       `json:"serial"`
	CSS     *string      `json:"css"`
	Members []string     `json:"members,omitempty"`
	Image   *cursorImage `json:"image,omitempty"`
}

// key is what a viewer can observe of an identity: a change of serial alone
// (Chrome recreating the same cursor) is not reported, while the arrow and
// the X, both answered as default, are two identities since they stand for
// different keywords.
func (c cursorIdentity) key() string {
	if c.CSS != nil {
		return "css:" + *c.CSS + " " + strings.Join(c.Members, " ")
	}
	return "image:" + c.Image.Hash
}

// cursorHash names a cursor image by its geometry and premultiplied pixels.
func cursorHash(width, height, hotX, hotY int, pixels []uint32) string {
	digest := sha256.New()
	var word [4]byte
	for _, value := range []uint32{uint32(width), uint32(height), uint32(hotX), uint32(hotY)} {
		binary.LittleEndian.PutUint32(word[:], value)
		digest.Write(word[:])
	}
	for _, pixel := range pixels {
		binary.LittleEndian.PutUint32(word[:], pixel)
		digest.Write(word[:])
	}
	return hex.EncodeToString(digest.Sum(nil)[:8])
}

// maximumCursorPictures bounds the page cursors a tracker keeps by hash.
const maximumCursorPictures = 32

// describe turns one XFixes cursor into its reported identity. The browser
// recreates a page's url() cursor, with a new serial, each time the pointer
// re-enters its element, so a picture is encoded once per hash and every
// later sighting reuses it.
func (t *cursorTracker) describe(serial uint32, width, height, hotX, hotY int, pixels []uint32) cursorIdentity {
	if width <= 0 || height <= 0 || width > maximumCursorSide || height > maximumCursorSide || len(pixels) != width*height {
		return arrow.identity(serial)
	}
	hash := cursorHash(width, height, hotX, hotY, pixels)
	if class, known := cursorClasses[hash]; known {
		return class.identity(serial)
	}
	picture, seen := t.pictures[hash]
	if !seen {
		picture = drawCursor(hash, cursorPixels{width, height, hotX, hotY, pixels})
		if t.pictures == nil {
			t.pictures = make(map[string]*cursorImage)
		}
		for evicted := range t.pictures {
			if len(t.pictures) < maximumCursorPictures {
				break
			}
			delete(t.pictures, evicted)
		}
		t.pictures[hash] = picture
	}
	if picture == nil {
		return arrow.identity(serial)
	}
	return cursorIdentity{Serial: serial, Image: picture}
}

// drawCursor is a page cursor's picture within the PNG budget, or nil when it
// cannot fit. Chrome rasterizes a page's cursor at the display's scale; one
// halving keeps an oversized image a picture of the same cursor at scale 1.
func drawCursor(hash string, source cursorPixels) *cursorImage {
	for scale := 2; scale >= 1; scale-- {
		if encoded := encodeCursorPNG(source); encoded != nil {
			return &cursorImage{Hash: hash, Width: source.width, Height: source.height, HotX: source.hotX, HotY: source.hotY, Scale: scale, PNG: encoded}
		}
		source = source.halved()
	}
	return nil
}

type cursorPixels struct {
	width, height, hotX, hotY int
	argb                      []uint32 // premultiplied, row-major
}

// halved averages each 2x2 block; premultiplied channels average linearly.
// The hotspot stays inside the image: an odd side's last column or row has no
// half of its own.
func (c cursorPixels) halved() cursorPixels {
	result := cursorPixels{width: max(1, c.width/2), height: max(1, c.height/2)}
	result.hotX, result.hotY = min(c.hotX/2, result.width-1), min(c.hotY/2, result.height-1)
	result.argb = make([]uint32, result.width*result.height)
	for y := 0; y < result.height; y++ {
		for x := 0; x < result.width; x++ {
			var sum [4]uint32
			for dy := 0; dy < 2; dy++ {
				for dx := 0; dx < 2; dx++ {
					pixel := c.argb[min(2*y+dy, c.height-1)*c.width+min(2*x+dx, c.width-1)]
					for channel := 0; channel < 4; channel++ {
						sum[channel] += pixel >> (8 * channel) & 255
					}
				}
			}
			var pixel uint32
			for channel := 0; channel < 4; channel++ {
				pixel |= (sum[channel] + 2) / 4 << (8 * channel)
			}
			result.argb[y*result.width+x] = pixel
		}
	}
	return result
}

// encodeCursorPNG writes premultiplied XFixes pixels as a straight-alpha PNG,
// or nothing when the result exceeds the budget.
func encodeCursorPNG(source cursorPixels) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, source.width, source.height))
	for index, argb := range source.argb {
		alpha := argb >> 24
		if alpha == 0 {
			continue
		}
		straight := func(channel uint32) uint8 { return uint8(min(255, channel*255/alpha)) }
		pixel := img.Pix[index*4 : index*4+4]
		pixel[0], pixel[1], pixel[2], pixel[3] = straight(argb>>16&255), straight(argb>>8&255), straight(argb&255), uint8(alpha)
	}
	var buf bytes.Buffer
	encoder := png.Encoder{CompressionLevel: png.BestCompression}
	if encoder.Encode(&buf, img) != nil || buf.Len() > maximumCursorPNG {
		return nil
	}
	return buf.Bytes()
}

// cursorTracker keeps the displayed cursor's identity current with no work
// per capture: CursorNotify events, recorded by the frame observer, trigger
// one GetCursorImageAndName round trip per new cursor object.
type cursorTracker struct {
	notified atomic.Uint64  // 1 + the newest notified serial; 0 before any
	known    bool           // a fetch has answered
	current  cursorIdentity // the cursor the last fetch found displayed
	reported string         // key of the identity last reported; "" before any
	// pictures holds each page cursor described so far, by hash; nil for one
	// that fits no budget. A picture is never changed once described.
	pictures map[string]*cursorImage
}

func (t *cursorTracker) notify(serial uint32) { t.notified.Store(uint64(serial) + 1) }

// begin issues a fetch when the newest cursor the server announced is not the
// one held, so its reply can be collected beside a capture's other replies.
// The comparison is with the cursor the last fetch found, never with the
// announcement that asked for it: the cursor can change while a fetch is in
// flight, and the browser shows an earlier cursor again under its earlier
// serial. With no announcement since the subscription, the cursor fetched is
// still the one displayed.
func (t *cursorTracker) begin(c *xgb.Conn) *xfixes.GetCursorImageAndNameCookie {
	if t.known {
		switch t.notified.Load() {
		case 0, uint64(t.current.Serial) + 1:
			return nil
		}
	}
	cookie := xfixes.GetCursorImageAndName(c)
	return &cookie
}

// finish resolves a fetch. An X protocol error means no cursor is displayed;
// the next capture asks again. Any other failure is the connection's.
func (t *cursorTracker) finish(cookie *xfixes.GetCursorImageAndNameCookie) error {
	if cookie == nil {
		return nil
	}
	reply, err := cookie.Reply()
	if err != nil {
		if _, protocol := err.(xgb.Error); protocol {
			return nil
		}
		return err
	}
	if t.known && reply.CursorSerial == t.current.Serial {
		return nil
	}
	t.known = true
	t.current = t.describe(reply.CursorSerial, int(reply.Width), int(reply.Height), int(reply.Xhot), int(reply.Yhot), reply.CursorImage)
	return nil
}

// unreported returns the current identity when it differs from the last one
// delivered, which is always so before the first delivery.
func (t *cursorTracker) unreported() *cursorIdentity {
	if identity := t.displayed(); identity != nil && identity.key() != t.reported {
		return identity
	}
	return nil
}

// displayed returns the current identity whether or not it was reported.
func (t *cursorTracker) displayed() *cursorIdentity {
	if !t.known {
		return nil
	}
	identity := t.current
	return &identity
}

// delivered records the identity a reply carried.
func (t *cursorTracker) delivered(identity *cursorIdentity) {
	if identity != nil {
		t.reported = identity.key()
	}
}
