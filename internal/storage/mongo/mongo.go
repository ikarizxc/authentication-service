package mongo

import (
	"context"
	"fmt"
	"os"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDB struct {
	client *mongo.Client
}

func New() (*MongoDB, error) {
	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		return nil, fmt.Errorf("you must set your 'MONGODB_URI' environment variable")
	}

	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}

	return &MongoDB{client}, nil
}

func (mongoDB *MongoDB) Disconnect() error {
	return mongoDB.client.Disconnect(context.TODO())
}

func (mongoDB *MongoDB) WriteRefreshToken(guid, refreshToken string) error {
	coll := mongoDB.client.Database("authentication-service").Collection("refresh-tokens")

	_, err := coll.InsertOne(context.TODO(), bson.M{
		"guid":         guid,
		"refreshToken": refreshToken,
	})

	if err != nil {
		return err
	}

	return nil
}
