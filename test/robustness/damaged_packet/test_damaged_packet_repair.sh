#!/bin/sh

$( dirname "$0" )/test_damaged_packet.sh repair $( basename "$0" ".sh" ) $@
exit $?

