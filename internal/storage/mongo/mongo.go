package mongo

import (
	"authentication-service/internal/tokens"
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

const (
	dbName   = "authentication-service"
	collName = "refresh-tokens"
)

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
	coll := mongoDB.client.Database(dbName).Collection(collName)

	doc := bson.M{
		"guid":         guid,
		"refreshToken": refreshToken,
	}

	_, err := coll.InsertOne(context.TODO(), doc)

	if err != nil {
		return err
	}

	return nil
}

func (mongoDB *MongoDB) UpdateRefreshToken(guid, refreshToken string) error {
	coll := mongoDB.client.Database(dbName).Collection(collName)

	filter := bson.M{"guid": guid}

	update := bson.D{{Key: "$set", Value: bson.D{{Key: "refreshToken", Value: refreshToken}}}}

	_, err := coll.UpdateOne(context.TODO(), filter, update)

	if err != nil {
		return err
	}

	return nil
}

func (mongoDB *MongoDB) ReadRefreshToken(guid string) (string, error) {
	coll := mongoDB.client.Database(dbName).Collection(collName)

	var readToken tokens.Token

	filter := bson.M{"guid": guid}

	err := coll.FindOne(context.TODO(), filter).Decode(&readToken)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", nil
		}

		return "", err
	}

	return readToken.RefreshToken, nil
}
