# 绕过frida检测抓取明文案例

## 序言

在我们平常挖洞的时候，很多app有抓包检测，frida检测，root检测等等
并且在绕过之后还有加密等着你

我们只需要看到明文请求和明文的响应就那么难吗

在理论上来说，虽然很多加密算法和发包操作实在so中完成的，但是数据包参数和url的构造很多都是在java中完成的，如果我们能hook到这个构造数据包的地方，也就相当于拿到了明文的请求

明文响应同理

和js打断点去直接改包，拿到请求是一样的逻辑

接下来我以一个昨天实战的app作为案例

感谢小凯，沐阳师傅的帮助

## root检测

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/cd80839a-37b8-4fd8-be5d-047208eba7ad)

参考
https://www.bilibili.com/read/cv15350941/
绕过

## frida检测

一hook就闪退

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/277c6169-c046-4215-837c-421d2fd1f4ff)

使用如下js
```
function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    console.log("load " + path);
                }
            }
        }
    );
}
hook_dlopen()
```

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/dc117db4-e198-439d-95c6-dc874396dacb)

hook加载so的函数，先看是哪个so文件导致的退出

发现是libmsaoaidsec.so

通过沐阳大佬给我的脚本，绕过了frida检测，抱歉不能放出来

思路是替换libmsaoaidsec.so的pthread_create函数

直接用原本的代码虽然可以绕过，但是再去attach模式hook这个应用会报错，可能是frida也用了这个函数，被我hook了，也搞不太清楚

我自己加上了try catch解决了这个问题

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/14bc4791-8f1d-49b2-aadb-46e4875bfd4a)

## 明文请求

抓包也有代理检测

用r0capture去抓包，查看堆栈

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/481cca8f-fc1d-4dea-8e61-61c8abdf53c5)

发现除了原生的类，就是TztNetWork.h这个类

因为绕过的js再运行，所以要使用objection的attach模式（-g后面加上pid就是attach模式，加上包名就是spawn）

```
frida-ps -Ua
```

能看到pid

hook这个类

```
android hooking watch class TztNetWork.h
```

发现调用了很多

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/fd08a967-a735-4ab6-9582-4090587fa5eb)

尝试hook前面几个方法

TztNetWork.h.F(TztNetWork.k)

```
android hooking watch class_method TztNetWork.h.F --dump-args --dump-return --dump-backtrace
```

```
(agent) [270220] Arguments TztNetWork.h.F(TztNetWork.k@7887369)
(agent) [270220] Called TztNetWork.h.F(TztNetWork.k)
(agent) [270220] Backtrace:
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.h.F(Native Method)
        TztNetWork.k.f(SourceFile:56)
        TztNetWork.k.p(SourceFile:60)
        TztNetWork.k.o(Unknown Source:2)
        com.lphtsccft.zhangle.foundation.network.a.B(SourceFile:302)
        com.lphtsccft.zhangle.foundation.network.i.n(SourceFile:139)
        com.lphtsccft.zhangle.foundation.web.local.AjaxEngineLocal.b(SourceFile:140)
        com.lphtsccft.zhangle.foundation.web.local.AjaxEngineLocal.a(SourceFile:234)
        yo.a.c(SourceFile:84)
        yo.a.d(SourceFile:149)
        yo.a.f(SourceFile:89)
        com.lphtsccft.zhangle.foundation.web.local.a.e0(SourceFile:98)
        com.lphtsccft.zhangle.foundation.web.d.shouldInterceptRequest(SourceFile:42)
        A8.a(chromium-TrichromeWebViewGoogle.apk-stable-447211483:15)
        org.chromium.android_webview.AwContentsBackgroundThreadClient.shouldInterceptRequestFromNative(chromium-TrichromeWebViewGoogle.apk-stable-447211483:2)
```

从打印的堆栈来看比较可能能看到明文信息的是这几个

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/9cb5c5d2-ee19-4d7a-aa9f-631e81b85fe2)

hook一下com.lphtsccft.zhangle.foundation.network.a.B这个方法

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/bcd022f1-39b5-4b0b-9052-a98d2cbfd050)

看不太懂，只能脱壳去看看代码了

frida-dexdump脱壳

并没有发现哪里可能可以看到明文的传输数据

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/5484bc9a-ac26-4aca-9b54-0102927cae97)

查看他的引用发现了com.lphtsccft.zhangle.foundation.network.i这个类的j方法

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/0f819c9e-d004-4ce6-9df0-3a5656bdf468)

看似像参数的拼接函数，hook这个方法
```
Java.perform(function () {
    

  let i = Java.use("com.lphtsccft.zhangle.foundation.network.i");
i["j"].implementation = function (str, i10, str2) {
    console.log(`i.j is called: str=${str}, i10=${i10}, str2=${str2}`);
    let result = this["j"](str, i10, str2);
    console.log(`i.j result=${result}`);
    return result;
};

  });
```

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/0e921116-77da-487c-bfbc-12c11655edd0)

hook引用他的方法，因为参数拼接应该是会被请求的类做引用

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/dcb2f951-df91-4ee7-8cde-c506ac6acc53)

还是看不明白，看看TztNetWork.k这个类

发现会调用这个方法

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/7d8ca3d7-c82f-4ccc-9844-0408b5995b92)

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/f45808be-4049-4918-9f37-687af357fc48)

再去看看TztNetWork.HS2013

在这个方法hook到返回包

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/0b875203-0aea-432e-8b7f-791605723abd)

```
Java.perform(function () {
    

  let HS2013 = Java.use("TztNetWork.HS2013");
HS2013["r"].implementation = function (str, str2) {
    console.log(`HS2013.r is called: str=${str}, str2=${str2}`);
    let result = this["r"](str, str2);
    console.log(`HS2013.r result=${result}`);
    return result;
};
  });
```

但是很遗憾

全是日志上报的返回包

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/5d27f120-d2f1-47ff-b176-2d06c0a67b44)

实际上我的手机做了一个查询操作肯定有一个正常业务的包

我在这里卡了很久，尝试了很久（几乎把带有TztNetWork的类hook完了），最终发现TztNetWork是只发上报日志的包的，也就是说之前r0capture没有抓到业务的数据包

于是我又看com.lphtsccft.zhangle.foundation.network.i这个类下的其他方法，既然这里做了参数和参数值的拼接，那么很有可能这里是核心构造数据包的地方

在hook了一堆方法之后，最终hook com.lphtsccft.zhangle.foundation.network.i.f方法输出了看得懂的

在几个日志请求中夹杂着一个业务请求，幸好眼睛看到了

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/6526266e-c139-40c5-b5fd-22cc979907b1)

打印一下他的堆栈

做一个if判断，不然又是一堆日志包

```
Java.perform(function () {
    

  let i = Java.use("com.lphtsccft.zhangle.foundation.network.i");
i["f"].implementation = function (str, str2) {
    // console.log(`i.f is called: str=${str}, str2=${str2}`);
    let result = this["f"](str, str2);
    if(str2 =="/alldata/detail"){console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));}
    
    // console.log(`i.f result=${result}`);
    return result;
};
  });
```

```
java.lang.Throwable
        at com.lphtsccft.zhangle.foundation.network.i.f(Native Method)
        at un.b.y(SourceFile:131)
        at yo.l.c(SourceFile:200)
        at yo.b$a.run(SourceFile:28)
        at java.util.concurrent.Executors$RunnableAdapter.call(Executors.java:462)
        at java.util.concurrent.FutureTask.run(FutureTask.java:266)
        at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1167)
        at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:641)
        at java.lang.Thread.run(Thread.java:920)
```

un.b.y这个方法看不懂，hook也看不懂

尝试yo.l.c这个方法

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/d3633a23-4acd-4101-95e6-83e7b4e41a8a)


![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/660bcae8-77b2-4552-914a-dadba35cea5e)

终于看到了明文请求

## 明文响应

返回的是webResourceResponse这个类

![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/0e0b8470-9dda-465d-a8ef-d94aee8bcfeb)

但是根据代码的逻辑发现会把json转为string，json从AjaxEngineLocal.c函数返回回来，也可以直接hook json的tostring但是肯定特别多输出，所以我们选择hook AjaxEngineLocal.c

```
Java.perform(function () {
    
  let AjaxEngineLocal = Java.use("com.lphtsccft.zhangle.foundation.web.local.AjaxEngineLocal");
AjaxEngineLocal["c"].implementation = function (hs2013) {
    console.log(`AjaxEngineLocal.c is called: hs2013=${hs2013}`);
    let result = this["c"](hs2013);
    console.log(`AjaxEngineLocal.c result=${result}`);
    return result;
};
  });
```


![image](https://github.com/chain00x/chain00x.github.io/assets/90015694/6e949388-a735-4df2-b271-f6584bbc2e33)

最终得到响应
