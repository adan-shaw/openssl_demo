###################
# makefile 阅读版(暂时不支持编译出.a or .so 库, 只支持编译出elf 执行文件.)
#
# 如需要编译出.a or .so 库, 可直接改写最后一步: '链接过程'即可.
# 其实没啥难度:
# 	链接生成静态库, 只需修改连接器为: ar;	而不是gcc or g++ or ld linker; 然后再改名字为: *.a
# 	链接生成动态库, 只需修改链接选项: 多加-shared -fPIC; 然后再改名字为: *.so
#
# 如需要编译出'多个目标文件', 同样需要修改最后一步, '链接过程'即可.
# 例如:
# 	$(CXX) -o obj_out_aes aes.o $(MY_PATH_L) $(LDFLAGS) 
# 	$(CXX) -o obj_out_des des.o $(MY_PATH_L) $(LDFLAGS) 
# 	$(CXX) -o obj_out_sha sha.o $(MY_PATH_L) $(LDFLAGS) 
# 	$(CXX) -o obj_out_md5 md5.o $(MY_PATH_L) $(LDFLAGS) 
#
# 注意:
# 每个'elf 输出文件', 对应链接哪个.o 文件, 这个关系必须描述清楚!!
# 一个'elf 输出文件', 只能有一个main() 函数！！ 
# 也就是, 每个'elf 输出文件'旗下的.o 文件中, 不能有多个main() 函数.
# 不同的'elf 输出文件'倒可以有2 个main() 函数
###################

# ((方法1: 直接让编译器自己找依赖关系, 自己只指出源文件所在, 不管编译过程, 
#         但是这样不影响使用, 编译出错同样会提示))
#
####################################################
# 注意: makefile 可以完美继承部分shell 命令, 如echo !!
#      makefile 同样可以使用: 
#      echo "hello" > tmp.txt 数据重定向> 到文件中, 
#      要不然make install 的时候, 你要怎样操作?? 
#      所以makefile 可以完美继承部分shell 功能
# 另外: shell 是没有goto 的
####################################################
#
#默认情况下, GNU make 工具在当前工作目录中按如下顺序搜索 makefile：
#    * GNUmakefile
#    * makefile
#    * Makefile
#    在 UNIX 系统中, 习惯使用 Makefile 作为 makfile 文件. 
#    make 命令指定某个makefile: (下面两种写法都可以)
#      make --file makefile all
#      make all --file makefile


# 目标声明
.PHONY: help clean check install all release all2 _all _release _all2 __all __release __all2


# 编译器/链接器选择
CC := gcc
CXX := g++
AR := ar


# c 编译选项
CFLAGS := -std=c11
#
# c/c++ 共有(由于CPPFLAGS 是c 和cpp 编译器共有的, 可能会发生混编, 
#           所以弃用, 保留c or cpp 分立的局面. 保留机动性)
#CPPFLAGS += -std=c++0x
#
# c++ 编译选项
CXXFLAGS := -std=c++0x

# 链接器参数的'初始化'(如:"-lld, -lpthread,-lrt 等")
# 另外:
# '编译'静态库, 不需要多加链接选项.
# '编译'动态库, 则只需要多加: -shared -fPIC 链接选项
LDFLAGS := -lssl -lcrypto


#
# 禁用的编译选项, 麻烦, 多事, 作用不大, 所以不改, 默认值即可
#
#  -static 此选项将禁止使用动态库
#  -share 此选项将尽量使用动态库
#  -x 指定编译语言标准


# posix 版本: 你不指定的话, gcc 默认也是使用posix 版本的标准.
# gnu 版本: 指定gnu 编译器编译标准, 编译之后可以开启如: -pg 等调试特性, 优化特性
DEFS := -D_GNU_SOURCE
#DEFS += -D_POSIX_SOURCE


#
# 编译选项/编译宏'特殊附加汇总'
#
# for 优化选项-O(默认), -O2, -O3 
# (无论调试与否, 优化选项都需要开启, 优化选项会自动修改代码执行顺序, 跟调试无关, 主要跟'代码逻辑'有关.)
# 要开启, 就debug, release 一起开启, 要关闭, 也一起关闭!!
OPTIMIZATION_OPTION := -O3

# for all _all __all (GNU 平台专用debug 编译选项)
ALL_CFLAGS := -ggdb3 -W -pg $(OPTIMIZATION_OPTION)
ALL_CXXFLAGS := -ggdb3 -W -pg $(OPTIMIZATION_OPTION)

# for release _release __release (通用发型版 编译选项)
RELEASE_CFLAGS := -w $(OPTIMIZATION_OPTION)
RELEASE_CXXFLAGS := -w $(OPTIMIZATION_OPTION)
RELEASE_DEFS := -DNDEBUG

# for all2 _all2 __all2 (通用debug 编译选项)
ALL2_CFLAGS := -g3 -W $(OPTIMIZATION_OPTION)
ALL2_CXXFLAGS := -g3 -W $(OPTIMIZATION_OPTION)





# 普通.h 头文件'路径'指认
HEAD_FILE_PATH := 


#
# 第三方'链接库'描述
#

# .a 静态'链接库'路径指认
LIB_STATIC_PATH := 
# .a 静态'链接库'头文件-路径指认
LIB_STATIC_HEAD_FILE_PATH := 
# .a 静态'链接库'文件指认 ( lib_static.a lib_static2.a )
LDFLAGS += 
# 不是找不到库的问题!! undefined reference to `lib_static_f1' 是其它原因!!
#LDFLAGS += ./src/lib_static/lib_static.a ./src/lib_static/lib_static2.a 
#LDFLAGS += lib_static.a lib_static2.a


# .so 动态'链接库'路径指认
LIB_DYNAMIC_PATH := 
# .so 动态'链接库'头文件-路径指认
LIB_DYNAMIC_HEAD_FILE_PATH := 
# .so 动态'链接库'文件指认 ( lib_dynamic.so )
LDFLAGS += 
#LDFLAGS += -l./src/lib_dynamic/lib_dynamic.so
# 告诉系统全局变量'LD_LIBRARY_PATH'装载'动态链接库'路径下的所有.so 文件
#export LD_LIBRARY_PATH=LD_LIBRARY_PATH:./src/lib_dynamic

#***
# 目标文件, := 实际上等于 =, 是一个赋值操作
TARGET := obj_out
LIB_STATIC_TARGET := obj_lib.a
LIB_DYNAMIC_TARGET := obj_out.so
#***


#
# 路径汇总
#
#MY_PATH_I := $(HEAD_FILE_PATH) $(LIB_STATIC_HEAD_FILE_PATH) $(LIB_DYNAMIC_HEAD_FILE_PATH) 
MY_PATH_I := $(LIB_STATIC_HEAD_FILE_PATH) $(LIB_DYNAMIC_HEAD_FILE_PATH) $(HEAD_FILE_PATH) 
MY_PATH_L := $(LIB_STATIC_PATH) $(LIB_DYNAMIC_PATH)


#>>>>>
# 方法: 直接让编译器自己找依赖关系, 自己只指出源文件所在, 不管编译过程, 
#       但是这样不影响使用, 编译出错同样会提示
#
# 在Makefile 规则中, <通配符>会被自动展开. 
# 但在变量的定义和函数引用时, 通配符将失效.
# 这种情况下就需要使用函数"wildcard", 它的用法是：$(wildcard PATTERN. )
# 一般我们可以使用"$(wildcard *.c)"来获取工作目录下的所有的.c文件列表. 
# 但是用了wildcard, 你就需要多加一个循环遍历, 很麻烦. 
# 还要用strip 去除空格
# 还要用subst 做字符串拼接. 
# 很麻烦！！
# 但是有一点, 通配符在当前文件夹内是有效的(总会被拆开), 
# 这样无论你加了什么gcc 前缀什么的, 都能拆开, 这样就完美了
# 你就可以用一个makefile 编译出所有的*.cpp 文件
#
#
# 注意: 多路径通配*.cpp 实际是安全的, 只是生成的.o 文件, 
# 会全部集中在当前目录下面, 所以你不能再像这样:
# __OBJS += ./no_assert/*.o ./make_project/*.o 定义了, 这是错误的. 
# 只需:
__ASS := *.s
__OBJS := *.o 
__SRC := ../demo/*.cpp
#__SRC_C := ./src/no_assert/*.c ./src/make_project/*.c
# 注意2: main() 所在的文件, 应该放到最后!! 
#       顺序问题也是会有的, 有时候会找不到main() 函数
#       调整一下<文件路径>的顺序即可
#
# 注意3: 你不需要指出所有.h 文件所在的地方, 
#       gcc 会自己根据路径找, 现在的gcc 高级了. 
#       所以实际只要-MM 一下, 只要找到了依赖, 
#       现在的编译器肯定可以找到对应的文件,
#       编译出问题同样会报告, 根本小题大造!! 这样已经是最简单的方式了. 
#<<<<<





# makefile 默认目标篡改(for eclipse)
default:all2

help:
	@echo ""
	@echo "passed, please make a choose target: make [target]"
	@echo "[target]::{"
	@echo "  help clean check install "
	@echo "  for .exe:       all     release    all2     "
	@echo "            -ggdb3 + -pg   -O2       -g3   "
	@echo "  for .a  :      _all    _release   __all2"
	@echo "  for .so :     __all   __release   __all2"
	@echo "}"
	@echo "demo:"
	@echo "make all for .exe"
	@echo ""
	@echo ""

clean:
	@echo ""
	rm obj_out_aes obj_out_des obj_out_3des obj_out_sha obj_out_md5 $(__OBJS) $(__ASS)
	@echo ">>clean up finish<<"
	@echo ""
	@echo ""

check:
	@echo ""
	@echo ">>all source file<<"
	#@echo $(__SRC_C)
	@echo $(__SRC)
	@echo ""
	@echo ">>checking all src<<"
	#$(CC) -MM $(__SRC_C)
	$(CXX) -MM $(__SRC)
	@echo ""
	@echo ">>make -E src<<"
	#$(CC) -E $(__SRC_C)
	$(CXX) -E $(__SRC)
	@echo ""
	@echo ""

install:
	@echo ""
	@echo ">>install needs root authority<<"
	@echo ""
	@echo ""





#
# for .exe
#
# 拦截游标, 硬性添加调试选项 -W = -Wextra = 打印一些额外警告信息
# -w 禁止显示所有警告信息
# -Wall 会打开一些很有用的警告选项(-W 的子集)
all:
	@echo ""
	@echo ">>building all src with [-ggdb3 -W -pg]<<"
	# 预编译和编译一起做
	#$(CC) $(CFLAGS) $(ALL_CFLAGS) $(DEFS) $(MY_PATH_I) -S $(__SRC_C) 
	$(CXX) $(CXXFLAGS) $(ALL_CXXFLAGS) $(DEFS) $(MY_PATH_I) -S $(__SRC)
	# 汇编
	#$(CC) -c $(__ASS)
	$(CXX) -c $(__ASS)
	# 链接
	$(CXX) -o obj_out_aes aes.o $(MY_PATH_L) $(LDFLAGS) 
	$(CXX) -o obj_out_des des.o $(MY_PATH_L) $(LDFLAGS) 
	$(CXX) -o obj_out_3des 3des.o $(MY_PATH_L) $(LDFLAGS) 
	$(CXX) -o obj_out_sha shaX.o $(MY_PATH_L) $(LDFLAGS) 
	$(CXX) -o obj_out_md5 md5.o $(MY_PATH_L) $(LDFLAGS) 
	#$(CC) -o $(TARGET) $(__OBJS) $(MY_PATH_L) $(LDFLAGS) 
	#调试(显示详细信息-检查-L, -I 比较适合)
	#$(CXX) -v $(MY_PATH_L) $(LDFLAGS) -o $(TARGET) $(__OBJS) # 这样的顺序是错误的, 请参考上面的顺序
	#$(CC) -v $(MY_PATH_L) $(LDFLAGS) -o $(TARGET) $(__OBJS)  # 链接文件的顺序很重要!
	@echo ">>make target-all finish<<"
	@echo ""
	@echo ""


# 追加宏定义-DNDEBUG (一般用来禁用assert())
release:
	@echo ""
	@echo ">>building all src with [-w -O2]<<"
	# 预编译和编译一起做
	#$(CC) $(CFLAGS) $(RELEASE_CFLAGS) $(DEFS) $(RELEASE_DEFS) $(MY_PATH_I) -S $(__SRC_C) 
	$(CXX) $(CXXFLAGS) $(RELEASE_CXXFLAGS) $(DEFS) $(RELEASE_DEFS) $(MY_PATH_I) -S $(__SRC) 
	# 汇编
	#$(CC) -c $(__ASS)
	$(CXX) -c $(__ASS)
	# 链接
	$(CXX) -o obj_out_aes aes.o $(MY_PATH_L) $(LDFLAGS) 
	$(CXX) -o obj_out_des des.o $(MY_PATH_L) $(LDFLAGS)
	$(CXX) -o obj_out_3des 3des.o $(MY_PATH_L) $(LDFLAGS) 
	$(CXX) -o obj_out_sha shaX.o $(MY_PATH_L) $(LDFLAGS)
	$(CXX) -o obj_out_md5 md5.o $(MY_PATH_L) $(LDFLAGS)
	#$(CC) -o $(TARGET) $(__OBJS) $(MY_PATH_L) $(LDFLAGS) 
	#调试(显示详细信息)
	#$(CXX) -v $(MY_PATH_L) $(LDFLAGS) -o $(TARGET) $(__OBJS) 
	#$(CC) -v $(MY_PATH_L) $(LDFLAGS) -o $(TARGET) $(__OBJS) 
	@echo ">>make target-release finish<<"
	@echo ""
	@echo ""


# 这个选项可以是供eclipse 调试, 
# 也可以是跨平台调试, 如freebsd 下面的gcc 编译器, IBM 下的gcc 编译器等. 
all2:
	@echo ""
	@echo ">>building all src with [-g3 -W]<<"
	# 预编译和编译一起做
	#$(CC) $(CFLAGS) $(ALL2_CFLAGS) $(DEFS) $(MY_PATH_I) -S $(__SRC_C) 
	$(CXX) $(CXXFLAGS) $(ALL2_CXXFLAGS) $(DEFS) $(MY_PATH_I) -S $(__SRC) 
	# 汇编
	#$(CC) -c $(__ASS)
	$(CXX) -c $(__ASS)
	# 链接
	$(CXX) -o obj_out_aes aes.o $(MY_PATH_L) $(LDFLAGS) 
	$(CXX) -o obj_out_des des.o $(MY_PATH_L) $(LDFLAGS) 
	$(CXX) -o obj_out_3des 3des.o $(MY_PATH_L) $(LDFLAGS) 
	$(CXX) -o obj_out_sha shaX.o $(MY_PATH_L) $(LDFLAGS) 
	$(CXX) -o obj_out_md5 md5.o $(MY_PATH_L) $(LDFLAGS) 
	#$(CC) -o $(TARGET) $(__OBJS) $(MY_PATH_L) $(LDFLAGS) 
	#调试(显示详细信息)
	#$(CXX) -v $(MY_PATH_L) $(LDFLAGS) -o $(TARGET) $(__OBJS) 
	#$(CC) -v $(MY_PATH_L) $(LDFLAGS) -o $(TARGET) $(__OBJS) 
	@echo ">>make target-all finish<<"
	@echo ""
	@echo ""





