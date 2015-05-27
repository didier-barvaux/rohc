################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the ROHC applications
################################################################################

if APP_PERF
APP_PERF_DIR = performance
else
APP_PERF_DIR =
endif

if APP_SNIFFER
APP_SNIFFER_DIR = sniffer
else
APP_SNIFFER_DIR =
endif

if APP_STATS
APP_STATS_DIR = stats
else
APP_STATS_DIR =
endif

SUBDIRS = \
	$(APP_PERF_DIR) \
	$(APP_SNIFFER_DIR) \
	$(APP_STATS_DIR)

