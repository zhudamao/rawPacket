######################################
#
# Generic makefile
#
# by George Foot
# email: george.foot@merton.ox.ac.uk
#
# Copyright (c) 1997 George Foot
# All rights reserved.
# 保留所有版权
#
# No warranty, no liability;
# you use this at your own risk.
# 没保险，不负责
# 你要用这个，你自己担风险
#
# You are free to modify and
# distribute this without giving
# credit to the original author.
# 你可以随便更改和散发这个文件
# 而不需要给原作者什么荣誉。
# （你好意思？）
#
######################################

### Customising
# 用户设定
#
# Adjust the following if necessary; EXECUTABLE is the target
# executable's filename, and LIBS is a list of libraries to link in
# (e.g. alleg, stdcx, iostr, etc). You can override these on make's
# command line of course, if you prefer to do it that way.
#
# 如果需要，调整下面的东西。 EXECUTABLE 是目标的可执行文件名， LIBS
# 是一个需要连接的程序包列表（例如 alleg, stdcx, iostr 等等）。当然你
# 可以在 make 的命令行覆盖它们，你愿意就没问题。
#


EXECUTABLE := a.out
LIBS := pthread pcap

RM-F :=	rm -f
RANLIB=ranlib

# Now alter any implicit rules' variables if you like, e.g.:
#
# 现在来改变任何你想改动的隐含规则中的变量，例如

ifdef XLS
CC := /opt/rmi/1.6/mipscross/crosstool/gcc-3.4.3-glibc-2.3.6/mipsisa32-xlr-linux/bin/mipsisa32-xlr-linux-gcc
else
CC := gcc
endif

#MYSQL_INCLUDE:= -I/usr/include/mysql
#MYSQL_LD:= -L/usr/lib/mysql

CFLAGS := -g -Wall -O2 -DRELAY_TO_USERCENTER  -DCONSOLE_COMMAND  -DLOG_UPDATE_BY_TIMER  -D__CHECK_LEAK  -DIMPORT_FILE_BUF  -DUSE_THREAD_POOL
CXXFLAGS := $(CFLAGS)

LD_FLAG := $(MYSQL_LD)

ifdef XLS
CFLAGS +=-I./fast_syscall -L./fast_syscall -I./user_mac -L./user_mac -g
endif

KERNEL_VER=$(shell uname -r)
KERNEL_DIR=/lib/modules/$(KERNEL_VER)/source/include
INCLUDE=-I$(KERNEL_DIR)

# You shouldn't need to change anything below this point.
#
# 从这里开始，你应该不需要改动任何东西。（我是不太相信，太ＮＢ了！）

SOURCE := $(wildcard *.c) $(wildcard *.cc) $(wildcard *.cpp)

# OBJS := $(patsubst %.c,%.o,$(patsubst %.cc,%.o,$(SOURCE)))
OBJS := $(patsubst %.c,%.o,$(patsubst %.cc,%.o,$(patsubst %.cpp,%.o,$(SOURCE))))


ifdef XLS
OBJS += ./user_mac/rmi_driver_intf_fast_syscall.o ./fast_syscall/fast_syscall.o
endif

DEPS := $(patsubst %.o,%.d,$(OBJS))
MISSING_DEPS := $(filter-out $(wildcard $(DEPS)),$(DEPS))
MISSING_DEPS_SOURCES := $(wildcard $(patsubst %.d,%.c,$(MISSING_DEPS)) \
$(patsubst %.d,%.cc,$(MISSING_DEPS)))
CPPFLAGS += -MMD

.PHONY : everything deps objs clean veryclean rebuild

everything : $(EXECUTABLE)

deps : $(DEPS)

objs : $(OBJS)


#	$(CC) $(CFLAGS)  -D_XOPEN_SOURCE=500 $<

clean :
	@$(RM-F) *.o
	@$(RM-F) *.d

veryclean: clean
	@$(RM-F) $(EXECUTABLE)

rebuild: veryclean everything

ifneq ($(MISSING_DEPS),)
$(MISSING_DEPS) :
	@$(RM-F) $(patsubst %.d,%.o,$@)    #删除.o 文件，引起.c 重新编译，重新生成 .d文件
endif

-include $(DEPS)

$(EXECUTABLE) : $(OBJS)
	$(CC) -g -o $(EXECUTABLE) $(OBJS) $(addprefix -l,$(LIBS)) $(LD_FLAG)

 
