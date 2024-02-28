# rust-coffloader

#### 尚未完工！
缺少对函数的重定向

目前已经实现了对COFF文件头的解析，可以运行text段的函数内容，可以重定向rdata段内容，尚不支持外部函数。

> cargo r -- hello.o
