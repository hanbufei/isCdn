package cmd

import (
	_ "embed"
	"github.com/hanbufei/isCdn/client"
	"github.com/hanbufei/isCdn/config"
)

type CdnCheck struct {
	client *client.Client
}

func New(config *config.BATconfig) CdnCheck {
	return CdnCheck{client: client.New(config)}
}

func (c *CdnCheck) Check(ip string) string {
	result := c.client.Check(ip)
	return result.String()
}
