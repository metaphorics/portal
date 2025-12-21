package wsjs

import (
	"errors"
	"syscall/js"
)

var (
	ErrFailedToDial = errors.New("failed to dial websocket")
	ErrClosed       = errors.New("websocket connection closed")
)

var (
	_WebSocket   = js.Global().Get("WebSocket")
	_ArrayBuffer = js.Global().Get("ArrayBuffer")
	_Uint8Array  = js.Global().Get("Uint8Array")
)

func readOptimizationsFlag() bool {
	value := js.Global().Get("__PORTAL_OPTIMIZATIONS__")
	if value.IsUndefined() || value.IsNull() {
		return true
	}
	if value.Type() == js.TypeBoolean {
		return value.Bool()
	}
	return true
}

var optimizationsEnabled = readOptimizationsFlag()

type Conn struct {
	ws js.Value

	messageChan chan []byte
	closeChan   chan struct{}

	funcsToBeReleased []js.Func
}

func (conn *Conn) freeFuncs() {
	for _, f := range conn.funcsToBeReleased {
		f.Release()
	}
}

func (conn *Conn) enqueueMessage(data []byte) {
	if !optimizationsEnabled {
		conn.messageChan <- data
		return
	}
	select {
	case conn.messageChan <- data:
		return
	default:
		// Drop oldest to keep queue bounded and avoid blocking JS callbacks.
		select {
		case <-conn.messageChan:
		default:
		}
		select {
		case conn.messageChan <- data:
		default:
		}
	}
}

func Dial(uri string) (*Conn, error) {
	errCh := make(chan error, 1)

	ws := _WebSocket.New(uri)
	ws.Set("binaryType", "arraybuffer")

	conn := &Conn{
		ws:          ws,
		messageChan: make(chan []byte, 128),
		closeChan:   make(chan struct{}, 1),
	}

	onOpen := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		errCh <- nil
		return nil
	})

	onError := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		errCh <- ErrFailedToDial
		return nil
	})

	onMessage := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		jsData := args[0].Get("data")
		if jsData.Type() == js.TypeString {
			// text frame
			data := []byte(jsData.String())

			conn.enqueueMessage(data)
		} else if jsData.InstanceOf(_ArrayBuffer) {
			// binary frame
			array := _Uint8Array.New(jsData)
			byteLength := array.Get("byteLength").Int()
			data := make([]byte, byteLength)
			js.CopyBytesToGo(data, array)

			conn.enqueueMessage(data)
		}

		return nil
	})

	onClose := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		close(conn.closeChan)
		return nil
	})

	conn.funcsToBeReleased = append(conn.funcsToBeReleased, onOpen, onError, onMessage, onClose)

	conn.ws.Call("addEventListener", "open", onOpen)
	conn.ws.Call("addEventListener", "error", onError)
	conn.ws.Call("addEventListener", "message", onMessage)
	conn.ws.Call("addEventListener", "close", onClose)

	err := <-errCh
	if err != nil {
		conn.freeFuncs()
		return nil, err
	}

	return conn, nil
}

func (conn *Conn) Close() error {
	conn.ws.Call("close")
	<-conn.closeChan
	conn.freeFuncs()
	return nil
}

func (conn *Conn) NextMessage() ([]byte, error) {
	select {
	case msg := <-conn.messageChan:
		return msg, nil
	case <-conn.closeChan:
		return nil, ErrClosed
	}
}

func (conn *Conn) Send(data []byte) error {
	buffer := _ArrayBuffer.New(len(data))
	array := _Uint8Array.New(buffer)
	js.CopyBytesToJS(array, data)

	conn.ws.Call("send", buffer)
	return nil
}
