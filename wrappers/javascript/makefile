run:
	cd ../../ && cargo build --release
	LIB_ARIES_ASKAR_PATH=~/Developer/work/essif/askar/aries-askar/target/release yarn nodejs start

run-with-log:
	cd ../../ && cargo build --release
	LOG=* LIB_ARIES_ASKAR_PATH=~/Developer/work/essif/askar/aries-askar/target/release yarn nodejs start

test:
	yarn nodejs test keys

test-with-log:
	cd ../../ && cargo build --release
	LIB_ARIES_ASKAR_PATH=~/Developer/work/essif/askar/aries-askar/target/release LOG=1 yarn nodejs test jose -t 'ecdh es direct'
