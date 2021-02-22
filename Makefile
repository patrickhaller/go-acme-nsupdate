include Makefile.golang

host := vps1.haller.ws

test:
	scp $(name) $(host):.


