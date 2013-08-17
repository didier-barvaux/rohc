#!/bin/sh

$( dirname "$0" )/test_lost_packet.sh norepair $( basename "$0" ".sh" ) $@
exit $?

