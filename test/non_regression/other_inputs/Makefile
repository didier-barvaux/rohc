
check: check_personal check_external

check_personal:
	./run_test.sh personal

check_external:
	./run_test.sh external

download::
	./get_captures.sh

clean:
	$(RM) inputs/*
	$(RM) logs/*

distclean: clean
	$(RM) download/*

