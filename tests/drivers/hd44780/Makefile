include ../Makefile.drivers_common

USEMODULE += hd44780

# disable native GPIOs for automatic test
ifneq (,$(filter native native64,$(BOARD)))
  USEMODULE += periph_gpio_mock
  # the same for Kconfig
  ifeq (1,$(TEST_KCONFIG))
    KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.native
  endif
endif


CFLAGS += -DHD44780_PARAM_PIN_RS=GPIO_PIN\(0,10\)
CFLAGS += -DHD44780_PARAM_PIN_RW=GPIO_UNDEF
CFLAGS += -DHD44780_PARAM_PIN_ENABLE=GPIO_PIN\(0,9\)
CFLAGS += -DHD44780_PARAM_PINS_DATA=\{GPIO_PIN\(1,13\),GPIO_PIN\(1,14\),GPIO_PIN\(1,15\),GPIO_PIN\(1,1\),GPIO_UNDEF,GPIO_UNDEF,GPIO_UNDEF,GPIO_UNDEF\}



include $(RIOTBASE)/Makefile.include
