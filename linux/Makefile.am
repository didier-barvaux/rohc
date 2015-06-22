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
	include \
	kmod/Makefile

all:
	$(MAKE) -C $(linux_kernel_src) M=$(abs_srcdir)/kmod

clean-local:
	if test -d $(linux_kernel_src) ; then $(MAKE) -C $(linux_kernel_src) M=$(abs_srcdir)/kmod clean ; fi
	$(RM) *.o .*.o.cmd
	$(RM) $(srcdir)/../src/common/protocols/.*.o.cmd
	$(RM) $(srcdir)/../src/common/schemes/.*.o.cmd
	$(RM) $(srcdir)/../src/common/.*.o.cmd
	$(RM) $(srcdir)/../src/comp/schemes/.*.o.cmd
	$(RM) $(srcdir)/../src/comp/.*.o.cmd
	$(RM) $(srcdir)/../src/decomp/schemes/.*.o.cmd
	$(RM) $(srcdir)/../src/decomp/.*.o.cmd

install:
	$(INSTALL) -d $(DESTDIR)/$(rohc_moddir)
	$(INSTALL) -m 644 $(builddir)/kmod/$(rohc_mod) $(DESTDIR)/$(rohc_moddir)/$(rohc_mod)
	$(INSTALL) -m 644 $(builddir)/kmod/$(rohc_test_mod) $(DESTDIR)/$(rohc_moddir)/$(rohc_test_mod)
	-/sbin/depmod -a

uninstall:
	rm -f $(DESTDIR)/$(rohc_moddir)/$(rohc_mod)
	rm -f $(DESTDIR)/$(rohc_moddir)/$(rohc_test_mod)
	-/sbin/depmod -a

