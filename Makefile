DERIVED := ./.build/xcode
AGENT_BIN := $(DERIVED)/Build/Products/Debug/GardenAgent

.PHONY: agent run-agent daemon schemes

schemes:
	xcodebuild -list

agent:
	xcodebuild build -scheme GardenAgent -configuration Debug \
	  -destination 'platform=macOS' -derivedDataPath $(DERIVED)

run-agent: agent
	$(AGENT_BIN)

daemon:
	cd crates/garden-daemon && ./run.sh
