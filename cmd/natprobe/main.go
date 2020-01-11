package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	cli "github.com/urfave/cli/v2"
	"go.universe.tf/natprobe/client"
	"go.universe.tf/natprobe/internal"
)

var logger = internal.NewLogger()

func main() {
	app := &cli.App{
		Name:   "natprobe",
		Usage:  "detect and characterize NAT devices",
		Action: run,
		Flags: []cli.Flag{
			// Probe servers
			&cli.StringSliceFlag{
				Name:  "servers",
				Usage: "prober servers to use",
				Value: cli.NewStringSlice("natprobe1.universe.tf.", "natprobe2.universe.tf."),
			},
			&cli.IntSliceFlag{
				Name:  "ports",
				Usage: "UDP ports to probe",
				Value: cli.NewIntSlice(internal.Ports...),
			},

			// DNS
			&cli.DurationFlag{
				Name:  "resolve-timeout",
				Usage: "DNS resolution timeout",
				Value: 3 * time.Second,
			},

			// Mapping
			&cli.DurationFlag{
				Name:  "mapping-duration",
				Usage: "NAT mapping probe duration",
				Value: 3 * time.Second,
			},
			&cli.DurationFlag{
				Name:  "mapping-tx-interval",
				Usage: "transmit interval for NAT mapping probes",
				Value: 200 * time.Millisecond,
			},
			&cli.IntFlag{
				Name:  "mapping-sockets",
				Usage: "number of mapping sockets to use",
				Value: 3,
			},

			// Firewall
			&cli.DurationFlag{
				Name:  "firewall-duration",
				Usage: "firewall probe duration",
				Value: 3 * time.Second,
			},
			&cli.DurationFlag{
				Name:  "firewall-tx-interval",
				Usage: "transmit interval for firewall probes",
				Value: 50 * time.Millisecond,
			},

			// Reporting
			&cli.BoolFlag{
				Name:  "print-results",
				Usage: "write the uninterpreted results to stdout",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "anonymize-results",
				Usage: "anonymize IP addresses in results",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "print-analysis",
				Usage: "write the interpreted analysis to stdout",
				Value: true,
			},
			&cli.StringFlag{
				Name:  "format",
				Usage: "output format for results and analyses (text or json)",
				Value: "text",
			},
		},
	}
	app.Run(os.Args)
}

func run(c *cli.Context) error {
	var printer func(interface{})
	switch c.String("format") {
	case "text":
		printer = textPrinter
	case "json":
		printer = jsonPrinter
	default:
		return fmt.Errorf("unknown --format value %q", c.String("format"))
	}

	opts := &client.Options{
		ServerAddrs:              c.StringSlice("servers"),
		Ports:                    c.IntSlice("ports"),
		ResolveDuration:          c.Duration("resolve-timeout"),
		MappingDuration:          c.Duration("mapping-duration"),
		MappingTransmitInterval:  c.Duration("mapping-tx-interval"),
		MappingSockets:           c.Int("mapping-sockets"),
		FirewallDuration:         c.Duration("firewall-duration"),
		FirewallTransmitInterval: c.Duration("firewall-tx-interval"),
	}

	result, err := client.Probe(context.Background(), opts)
	if err != nil {
		return err
	}

	if c.Bool("anonymize-results") {
		result.Anonymize()
	}
	if c.Bool("print-results") {
		printer(result)
	}
	if c.Bool("print-analysis") {
		printer(result.Analyze())
	}
	return nil
}

func textPrinter(obj interface{}) {
	fmt.Println(obj)
}

func jsonPrinter(obj interface{}) {
	bs, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(bs))
}
