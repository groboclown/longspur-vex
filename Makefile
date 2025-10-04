
export PATH := $(PATH):$(shell go env GOPATH)/bin

GO := go

OUTDIR=target
BASE_BINARY_NAME=longspur
ifeq ($(OS),Windows_NT)
	BINARY_NAME=$(BASE_BINARY_NAME).exe
else
	BINARY_NAME=$(BASE_BINARY_NAME)
endif

SRC_FILES=$(shell find . -type f -name "*.go")
VERSION=$(file <version.txt)


# =====================================================================
# Top level, easy to remember, targets.
# These build just for the current OS/ARCH.
# They also build-up their actual work under each resource's description.

.PHONY: build
build:

.PHONY: clean
clean:

.PHONY: sbom
sbom:

.PHONY: all
all: clean build sbom


# =====================================================================
build: $(OUTDIR)/$(BINARY_NAME)
$(OUTDIR)/$(BINARY_NAME): $(OUTDIR) $(SRC_FILES)
	$(GO) build -o $(OUTDIR)/$(BINARY_NAME) ./cmd/longspur/

$(OUTDIR):
	mkdir -p $(OUTDIR)

# No clean for outdir.

clean: clean-$(BINARY_NAME)

.PHONY: clean-$(BINARY_NAME)
clean-$(BINARY_NAME):
	rm -f $(OUTDIR)/$(BINARY_NAME) || true

sbom: $(OUTDIR)/$(BASE_BINARY_NAME).cdx.json
$(OUTDIR)/$(BASE_BINARY_NAME).cdx.json: go.mod go.sum get-sbom-tools
	cyclonedx-gomod app \
	  -json \
	  -output $(OUTDIR)/$(BASE_BINARY_NAME).cdx.json \
	  -output-version 1.6 \
	  -main cmd/longspur


# =====================================================================
build: test
test:
	$(GO) test -v ./...


# =====================================================================
# Some general targets.

.PHONY: get-sbom-tools
get-sbom-tools:
	$(GO) install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest


# =====================================================================
# Multi-arch builds

.PHONY: multi-all
multi-all: multi-clean multi-build multi-sbom

.PHONY: multi-build
multi-build:
.PHONY: multi-sbom
multi-sbom:

# Macro for building for a specific OS/ARCH combination.
define OS_BUILD

$(eval B_OS = $(1))
$(eval B_ARCH = $(2))
$(eval OS_EXT = $(3))
$(eval OS_OUTDIR=$(OUTDIR)/$(B_OS)-$(B_ARCH))
$(eval EXEC_NAME=$(OS_OUTDIR)/$(BASE_BINARY_NAME)-$(B_OS)-$(B_ARCH)$(OS_EXT))
$(eval SBOM_NAME=$(OS_OUTDIR)/$(BASE_BINARY_NAME)-$(B_OS)-$(B_ARCH).cdx.json)

multi-build: $(EXEC_NAME)
multi-sbom: $(SBOM_NAME)

$(OS_OUTDIR):
	mkdir -p $(OS_OUTDIR)

clean: clean-$(B_OS)-$(B_ARCH)

.PHONY: clean-$(B_OS)-$(B_ARCH)
clean-$(B_OS)-$(B_ARCH):
	rm -f $(EXEC_NAME) $(SBOM_NAME) || true

$(EXEC_NAME): $(OS_OUTDIR) $(SRC_FILES)
	GOOS=$(B_OS) GOARCH=$(B_ARCH) $(GO) build -o $(EXEC_NAME) ./cmd/longspur/

$(SBOM_NAME): go.mod go.sum get-sbom-tools
	GOOS=$(B_OS) GOARCH=$(B_ARCH) cyclonedx-gomod app \
	  -json \
	  -output $(SBOM_NAME) \
	  -output-version 1.6 \
	  -main cmd/longspur

clean: clean-$(SBOM_NAME)

.PHONY: clean-$(SBOM_NAME)
clean-$(SBOM_NAME):
	rm -f $(SBOM_NAME) || true

endef

# Supported platforms.
$(eval $(call OS_BUILD,linux,amd64,))
$(eval $(call OS_BUILD,linux,arm64,))
$(eval $(call OS_BUILD,windows,amd64,.exe))
$(eval $(call OS_BUILD,darwin,amd64,))
$(eval $(call OS_BUILD,darwin,arm64,))

