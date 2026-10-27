CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -pthread
LDFLAGS ?= -pthread
TARGET = proxy_server
SOURCES = networking/server.c networking/connection_handler.c http/http_parser.c http/forwarder.c security/access_control.c security/cache.c monitoring/logger.c monitoring/error_handler.c monitoring/performance.c
.PHONY: all clean test
all: $(TARGET)
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $@ $(LDFLAGS)
clean:
	rm -f $(TARGET) proxy.log
test:
	bash tests/smoke_test.sh
