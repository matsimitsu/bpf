probe:
	docker run  -v "$$PWD":/build bpf-build /bin/sh -c 'cd bpf_probe && cargo bpf build'
loader:
	docker run  -v "$$PWD":/build bpf-build /bin/sh -c 'cd bpf_loader && cargo build'
docker:
	cd bpf_probe && docker build -t bpf-build .
