package main

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"go.universe.tf/natprobe/client"
)

func main() {
	result, err := client.Probe(context.Background(), nil)
	if err != nil {
		logrus.Fatalf("Probe failed: %s", err)
	}
	result.Anonymize()
	fmt.Println(result.Analyze().Narrative())
}
