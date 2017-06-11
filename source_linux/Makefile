obj-m += mod.o
mod-objs :=  ./src/mem_handling.o ./src/main.o ./src/injector.o ./src/data.o
cc-flags := -g

 
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
