CC ?= cc
CFLAGS := -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-sanitize-recover=all

test_core: test_core.c ../module/bcn_core.h
	$(CC) $(CFLAGS) -o $@ $<

check: test_core
	./test_core

clean:
	rm -f test_core

.PHONY: check clean
