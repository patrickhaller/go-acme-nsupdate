host := vps1.haller.ws
name := go-acme-nsupdate

test:
	scp ~/var/go/bin/$(name) $(host):.


include ~/pkg/make/Makefile.golang
