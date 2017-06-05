
check: check_personal check_external

check_personal:
	./run_tests.sh personal

check_external:
	./run_tests.sh external

download::
	./get_captures.sh

clean:
	$(RM) inputs/*
	$(RM) logs/*

distclean: clean
	$(RM) download/*

