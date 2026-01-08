# Simple Makefile - Binaries in current directory

CARGO := cargo
COORD := coordinator
PARTY := party
RELEASE_DIR := target/release

# 声明伪目标
.PHONY: all coord party clean

# all 依赖伪目标
all: coord party

# 构建协调者
coord:
	@echo "Building coordinator..."
	@$(CARGO) build --release --bin $(COORD)
	@if [ -f "$(RELEASE_DIR)/$(COORD)" ]; then \
		cp -f "$(RELEASE_DIR)/$(COORD)" . && echo "✅ coordinator created in current directory"; \
	elif [ -f "$(RELEASE_DIR)/$(COORD).exe" ]; then \
		cp -f "$(RELEASE_DIR)/$(COORD).exe" "./$(COORD)" && echo "✅ coordinator.exe renamed to coordinator in current directory"; \
	else \
		echo "❌ Failed to find coordinator binary"; \
		exit 1; \
	fi

# 构建参与者
party:
	@echo "Building party..."
	@$(CARGO) build --release --bin $(PARTY)
	@if [ -f "$(RELEASE_DIR)/$(PARTY)" ]; then \
		cp -f "$(RELEASE_DIR)/$(PARTY)" . && echo "✅ party created in current directory"; \
	elif [ -f "$(RELEASE_DIR)/$(PARTY).exe" ]; then \
		cp -f "$(RELEASE_DIR)/$(PARTY).exe" "./$(PARTY)" && echo "✅ party.exe renamed to party in current directory"; \
	else \
		echo "❌ Failed to find party binary"; \
		exit 1; \
	fi

# 清理
clean:
	@echo "Cleaning..."
	@$(CARGO) clean
	@rm -f $(COORD) $(COORD).exe $(PARTY) $(PARTY).exe 2>/dev/null || true
	@echo "✅ Clean complete"

# 帮助
help:
	@echo "Usage:"
	@echo "  make           - Build both binaries (coordinator and party)"
	@echo "  make coord     - Build coordinator only"
	@echo "  make party     - Build party only"
	@echo "  make clean     - Clean all build artifacts"
	@echo "  make help      - Show this help"