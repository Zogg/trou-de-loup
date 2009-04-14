obj-m += debug_reg_3.o
debug_reg_3-objs += debug_reg_3.o sebek.o net.o util.o filter.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
