.PHONY: all
all:
	go test ./...
	(cd cli && CGO_ENABLED=0 go build .)
	(cd server && CGO_ENABLED=0 go build .)

.PHONY: deploy
deploy: all
	scp server/server root@natprobe1:/opt/natprobe2
	scp server/natprobe.service root@natprobe1:/etc/systemd/system/natprobe.service
	ssh root@natprobe1 'mv -f /opt/natprobe2 /opt/natprobe && systemctl daemon-reload && systemctl restart natprobe'
