default: tests.log

include ../../src/config.inc
include ../../src/common

ifeq ($(filter-out OSX MSVC,$(BUILD_ENV_)),)
	# no POSIX threads on Windows
	# for OSX we'd need sound handling of pointers in multi-threaded programs
	no_pthread = -X pthread
endif

ifeq ($(BUILD_ENV_),MSVC)
	exclusion=$(no_pthread) -X gcc-only
else
	exclusion=$(no_pthread)
endif

test:
	@../test.pl -e -p -c "../../../src/cbmc/cbmc --validate-goto-model --validate-ssa-equation" $(exclusion)

tests.log: ../test.pl
	@../test.pl -e -p -c "../../../src/cbmc/cbmc --validate-goto-model --validate-ssa-equation" $(exclusion)

show:
	@for dir in *; do \
		if [ -d "$$dir" ]; then \
			vim -o "$$dir/*.c" "$$dir/*.out"; \
		fi; \
	done;

clean:
	find -name '*.out' -execdir $(RM) '{}' \;
	find -name '*.gb' -execdir $(RM) '{}' \;
	$(RM) tests.log
