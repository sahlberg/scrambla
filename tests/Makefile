SMB2_TESTS = $(subst .py, , $(sort $(wildcard test_smb2_*.py)))

all: smb2_tests

smb2_tests: $(SMB2_TESTS)

% :: %.py
	@echo "Running" $@
	@PYTHONPATH=.. python $<

