################################
# The usual RIOT example setup #
################################

# name of your application -- needs to match Cargo.toml crate name
APPLICATION = coap_demo

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/..

USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules
USEMODULE += gnrc_ipv6_default
USEMODULE += gcoap
# Additional networking modules that can be dropped if not needed
USEMODULE += gnrc_icmpv6_echo

USEMODULE += shell
USEMODULE += shell_cmds_default

USEMODULE += ps
USEMODULE += saul_default


USEMODULE += ztimer_usec
USEMODULE += ztimer_msec

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

# ... and with two CoAP stacks we need a tad more room
CFLAGS += '-DTHREAD_STACKSIZE_MAIN=(THREAD_STACKSIZE_DEFAULT + 12000)'

######################################################
# Set up Rust on RIOT                                #
######################################################

APPLICATION_RUST_MODULE = $(APPLICATION)
BASELIBS += $(APPLICATION_RUST_MODULE).module

FEATURS_REQUIRED += rust_target

######################################################
# Load the RIOT make infrastructure                  #
######################################################

include $(RIOTBASE)/Makefile.include
