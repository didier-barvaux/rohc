
WIRESHARK_BASE_PATH=~/.wireshark/
WIRESHARK_PLUGINS_PATH=$(WIRESHARK_BASE_PATH)/plugins/
WIRESHARK_LUA_INIT_FILE=$(WIRESHARK_BASE_PATH)/init.lua

all:
	cat README.md


install: install_files enable_lua

install_files:
	@echo '========= install files'
	mkdir -p $(WIRESHARK_BASE_PATH)
	mkdir -p $(WIRESHARK_PLUGINS_PATH)
	cp -f *.lua $(WIRESHARK_PLUGINS_PATH)
	cp -Rf rohc_rfc3095/ $(WIRESHARK_PLUGINS_PATH)
	@echo
	@echo

enable_lua:
	@echo '========= enable Lua dissectors'
	grep -qE 'disable_lua = false' $(WIRESHARK_LUA_INIT_FILE) \
		|| echo 'disable_lua = false'  >> $(WIRESHARK_LUA_INIT_FILE)
	@echo
	@echo


check: check_uncompressed check_icmp check_udp

check_uncompressed:
	@echo '========= dissect ROHCv1 Uncompressed packet'
	tshark -V -c 1 -r ../../test/non_regression/rfc3095/inputs/ipvx/rohc_maxcontexts0_wlsb4_smallcid.pcap 
	@echo
	@echo

check_icmp:
	@echo '========= dissect ROHCv1 IP-only packet'
	tshark -V -c 1 -r ../../test/non_regression/rfc3095/inputs/ipv4/icmp/rohc_maxcontexts0_wlsb4_smallcid.pcap 
	@echo
	@echo

check_udp:
	@echo '========= dissect ROHCv1 IP/UDP packet'
	tshark -V -c 1 -r ../../test/non_regression/rfc3095/inputs/ipv4/udp/rohc_maxcontexts0_wlsb4_smallcid.pcap 
	@echo
	@echo

