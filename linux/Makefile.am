################################################################################
#	Name       : Makefile
#	Authors    : Mikhail Gruzdev <michail.gruzdev@gmail.com>
#	             Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	             Thales Communications
#	Description: Build a test module for Linux kernel
#	             (for the ROHC library build system)
################################################################################


rohc_modname = rohc
rohc_mod = $(rohc_modname).ko

rohc_test_modname = rohc_test
rohc_test_mod = $(rohc_test_modname).ko

rohc_moddir = /lib/modules/`uname -r`/extra

EXTRA_DIST = \
	kmod.c \
	kmod_test.c \
	include/ \
	kmod/Makefile

all:
	$(MAKE) -C $(linux_kernel_src) M=$(abs_srcdir)/kmod

install:
	$(INSTALL) -d $(DESTDIR)/$(rohc_moddir) -f Makefile.linux
	$(INSTALL) -m 644 $(rohc_mod) $(DESTDIR)/$(rohc_moddir)/$(rohc_mod)
	$(INSTALL) -m 644 $(rohc_test_mod) $(DESTDIR)/$(rohc_moddir)/$(rohc_test_mod)
	-/sbin/depmod -a

uninstall:
	rm -f $(DESTDIR)/$(rohc_moddir)/$(rohc_mod)
	rm -f $(DESTDIR)/$(rohc_moddir)/$(rohc_test_mod)
	-/sbin/depmod -a

