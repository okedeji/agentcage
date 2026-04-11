package findings

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type MessageHandler func(ctx context.Context, msg Message) error

type Subscription interface {
	Stop()
}

type Bus interface {
	CreateStream(ctx context.Context, assessmentID string) error
	DeleteStream(ctx context.Context, assessmentID string) error
	Publish(ctx context.Context, assessmentID string, msg Message) error
	Subscribe(ctx context.Context, assessmentID string, handler MessageHandler) (Subscription, error)
	Close()
}

type NATSBus struct {
	conn *nats.Conn
	js   jetstream.JetStream
}

func NewNATSBus(url string, opts ...nats.Option) (*NATSBus, error) {
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("connecting to NATS at %s: %w", url, err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("creating JetStream context: %w", err)
	}
	return &NATSBus{conn: nc, js: js}, nil
}

func streamName(assessmentID string) string {
	return "findings-" + assessmentID
}

func consumerName(assessmentID string) string {
	return "findings-consumer-" + assessmentID
}

func (b *NATSBus) CreateStream(ctx context.Context, assessmentID string) error {
	_, err := b.js.CreateStream(ctx, jetstream.StreamConfig{
		Name:      streamName(assessmentID),
		Subjects:  []string{Subject(assessmentID)},
		Retention: jetstream.WorkQueuePolicy,
		MaxMsgs:   -1,
		MaxBytes:  -1,
	})
	if err != nil {
		return fmt.Errorf("creating stream for assessment %s: %w", assessmentID, err)
	}
	return nil
}

func (b *NATSBus) DeleteStream(ctx context.Context, assessmentID string) error {
	err := b.js.DeleteStream(ctx, streamName(assessmentID))
	if err != nil {
		return fmt.Errorf("deleting stream for assessment %s: %w", assessmentID, err)
	}
	return nil
}

func (b *NATSBus) Publish(ctx context.Context, assessmentID string, msg Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling finding message for assessment %s: %w", assessmentID, err)
	}
	_, err = b.js.Publish(ctx, Subject(assessmentID), data)
	if err != nil {
		return fmt.Errorf("publishing finding to assessment %s: %w", assessmentID, err)
	}
	return nil
}

func (b *NATSBus) Subscribe(ctx context.Context, assessmentID string, handler MessageHandler) (Subscription, error) {
	cons, err := b.js.CreateOrUpdateConsumer(ctx, streamName(assessmentID), jetstream.ConsumerConfig{
		Name:          consumerName(assessmentID),
		Durable:       consumerName(assessmentID),
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    3,
		FilterSubject: Subject(assessmentID),
	})
	if err != nil {
		return nil, fmt.Errorf("creating consumer for assessment %s: %w", assessmentID, err)
	}

	cctx, err := cons.Consume(func(m jetstream.Msg) {
		var msg Message
		if err := json.Unmarshal(m.Data(), &msg); err != nil {
			_ = m.Nak() // best-effort nak, redelivery will retry with the same data
			return
		}
		if err := handler(ctx, msg); err != nil {
			_ = m.Nak()
			return
		}
		_ = m.Ack() // best-effort ack, JetStream will redeliver if this fails
	})
	if err != nil {
		return nil, fmt.Errorf("starting consume for assessment %s: %w", assessmentID, err)
	}

	return &natsSub{cctx: cctx}, nil
}

func (b *NATSBus) Close() {
	b.conn.Close()
}

type natsSub struct {
	cctx jetstream.ConsumeContext
}

func (s *natsSub) Stop() {
	s.cctx.Stop()
}
