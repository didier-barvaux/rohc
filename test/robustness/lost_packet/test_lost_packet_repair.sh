#!/bin/sh

$( dirname "$0" )/test_lost_packet.sh repair $( basename "$0" ".sh" ) $@
exit $?

