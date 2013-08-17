#!/bin/sh

$( dirname "$0" )/test_damaged_packet.sh norepair $( basename "$0" ".sh" ) $@
exit $?

